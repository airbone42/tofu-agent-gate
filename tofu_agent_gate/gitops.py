"""Git-Abläufe des Runners: Branches holen, prüfen, mergen, aufräumen."""

from __future__ import annotations

import fnmatch
import re
import shutil
from dataclasses import dataclass
from pathlib import Path

from . import proc
from .config import Config

BRANCH_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")


class GitError(RuntimeError):
    pass


@dataclass
class Branch:
    name: str  # ohne "origin/"
    head: str


class Git:
    def __init__(self, cfg: Config, env: dict[str, str] | None = None):
        self.cfg = cfg
        self.dir = cfg.repo.workdir
        self.env = proc.base_env(env or {})
        self.env.update({
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_AUTHOR_NAME": cfg.repo.author_name,
            "GIT_AUTHOR_EMAIL": cfg.repo.author_email,
            "GIT_COMMITTER_NAME": cfg.repo.author_name,
            "GIT_COMMITTER_EMAIL": cfg.repo.author_email,
        })
        if cfg.repo.ssh_key:
            self.env["GIT_SSH_COMMAND"] = f"ssh -i {cfg.repo.ssh_key} -o IdentitiesOnly=yes -o BatchMode=yes"

    def _git(self, *args: str, cwd: Path | None = None, check: bool = True) -> proc.Result:
        r = proc.run(["git", *args], cwd=cwd or self.dir, env=self.env, timeout=300)
        if check and not r.ok:
            raise GitError(f"git {args[0]} fehlgeschlagen: {r.tail(5)}")
        return r

    def ensure_clone(self) -> None:
        if (self.dir / ".git").exists():
            return
        self.dir.parent.mkdir(parents=True, exist_ok=True)
        r = proc.run(["git", "clone", "--no-checkout", self.cfg.repo.url, str(self.dir)], env=self.env, timeout=600)
        if not r.ok:
            raise GitError(f"git clone fehlgeschlagen: {r.tail(5)}")

    def fetch(self) -> None:
        self._git("fetch", "--prune", "--quiet", "origin")

    def rev(self, ref: str) -> str:
        return self._git("rev-parse", "--verify", f"{ref}^{{commit}}").out.strip()

    def desired_branches(self) -> list[Branch]:
        prefix = self.cfg.repo.branch_prefix
        out = self._git("for-each-ref", "--format=%(refname:strip=3) %(objectname)",
                        f"refs/remotes/origin/{prefix}").out
        branches = []
        for line in out.splitlines():
            name, _, head = line.partition(" ")
            if name.startswith(prefix):
                branches.append(Branch(name, head))
        return sorted(branches, key=lambda b: b.name)

    def valid_name(self, name: str) -> bool:
        rest = name[len(self.cfg.repo.branch_prefix):]
        return name.startswith(self.cfg.repo.branch_prefix) and bool(BRANCH_RE.match(rest))

    def message(self, commit: str) -> str:
        return self._git("log", "-1", "--format=%B", commit).out.strip()

    def changed_paths(self, base: str, head: str) -> list[str]:
        out = self._git("diff", "--name-only", "--no-renames", f"{base}...{head}").out
        return [p for p in out.splitlines() if p]

    def disallowed_paths(self, base: str, head: str) -> list[str]:
        allowed = self.cfg.repo.allowed_paths
        return [p for p in self.changed_paths(base, head)
                if not any(fnmatch.fnmatchcase(p, pat) for pat in allowed)]

    def worktree(self, path: Path, commit: str) -> Path:
        if path.exists():
            self.remove_worktree(path)
        self._git("worktree", "add", "--detach", "--force", str(path), commit)
        return path

    def remove_worktree(self, path: Path) -> None:
        self._git("worktree", "remove", "--force", str(path), check=False)
        if path.exists():
            shutil.rmtree(path, ignore_errors=True)
        self._git("worktree", "prune", check=False)

    def merge_into(self, wt: Path, branch_head: str, message: str) -> str:
        """Im Worktree (auf main) den Branch mergen. Gibt den Merge-Commit zurück."""
        r = self._git("merge", "--no-ff", "--no-edit", "-m", message, branch_head, cwd=wt, check=False)
        if not r.ok:
            self._git("merge", "--abort", cwd=wt, check=False)
            raise GitError(f"Merge-Konflikt: {r.tail(5)}")
        return self._git("rev-parse", "HEAD", cwd=wt).out.strip()

    def push_main(self, commit: str) -> None:
        self._git("push", "--quiet", "origin", f"{commit}:refs/heads/{self.cfg.repo.main}")

    def delete_branch(self, name: str) -> None:
        self._git("push", "--quiet", "origin", "--delete", name, check=False)

    def checkout(self, wt: Path, commit: str) -> None:
        self._git("checkout", "--detach", "--force", commit, cwd=wt)
        self._git("clean", "-fdx", "-e", ".terraform/", cwd=wt)
