"""Ablauf je Agenten-Branch: Plan, Policy, Freigabe, Apply, Prüfung, Rollback."""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Protocol

from . import plan as planlib
from . import proc
from .config import Config
from .gitops import Branch, Git, GitError
from .hooks import Hooks
from .policy import Decision, Policy, classify
from .redact import redact_data

log = logging.getLogger(__name__)


def short_reason(text: str | None, limit: int = 300) -> str:
    """Technische Fehlertexte auf eine verständliche Zeile kürzen."""
    lines = [ln.strip() for ln in (text or "").splitlines() if ln.strip()]
    if not lines:
        return ""
    head = lines[0].rstrip(":")
    api = next((m.group(0) for ln in lines if (m := re.search(r"api\.err\.\w+", ln))), None)
    if api:
        out = f"{head}: UniFi lehnt ab ({api})"
    else:
        err = next((ln for ln in lines if ln.startswith("Error:")), None)
        out = f"{head}: {err[6:].strip()}" if err and err != lines[0] else head
    return out if len(out) <= limit else out[: limit - 1] + "…"


class Approver(Protocol):
    def request(self, *, plan_hash: str, summary: str, agent_reason: str | None = None,
                link: str | None = None, timeout_s: int = 1800) -> Any: ...

    def notify(self, text: str) -> None: ...


class Deadman(Protocol):
    def schedule(self, run_id: str) -> None: ...

    def cancel(self, run_id: str) -> None: ...


@dataclass
class Run:
    run_id: str
    branch: str
    head: str
    status: str = "started"
    level: str | None = None
    reasons: list[str] = field(default_factory=list)
    plan_hash: str | None = None
    last_good: str | None = None
    merge_commit: str | None = None
    pid: int | None = None
    started: float = 0.0
    finished: float | None = None
    summary: str = ""

    def save(self, runs_dir: Path) -> None:
        runs_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = runs_dir / f"{self.run_id}.json"
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(redact_data(asdict(self)), indent=2, ensure_ascii=False), encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)

    @classmethod
    def load(cls, runs_dir: Path, run_id: str) -> Run:
        data = json.loads((runs_dir / f"{run_id}.json").read_text(encoding="utf-8"))
        return cls(**data)


@dataclass
class Deps:
    git: Git
    tofu_factory: Callable[[Path], Any]
    hooks: Hooks
    policy: Policy
    deadman: Deadman
    approver: Approver | None = None
    redact: Callable[[str], str] = lambda s: s
    clock: Callable[[], float] = time.time


class Runner:
    def __init__(self, cfg: Config, deps: Deps):
        self.cfg = cfg
        self.d = deps

    # ------------------------------------------------------------ Hilfen

    def _notify(self, text: str) -> None:
        text = self.d.redact(text)
        log.info("Meldung: %s", text)
        if self.d.approver:
            try:
                self.d.approver.notify(text)
            except Exception as e:  # Meldungen dürfen den Ablauf nie abbrechen
                log.warning("Meldung fehlgeschlagen: %s", type(e).__name__)

    def _run_dir(self, run_id: str) -> Path:
        p = self.cfg.state_dir / "work" / run_id
        p.mkdir(parents=True, exist_ok=True, mode=0o700)
        return p

    def _seen_path(self) -> Path:
        return self.cfg.state_dir / "seen.json"

    def _seen(self) -> dict[str, str]:
        try:
            return json.loads(self._seen_path().read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def _mark_seen(self, branch: Branch, run_id: str) -> None:
        seen = self._seen()
        seen[f"{branch.name}@{branch.head}"] = run_id
        tmp = self._seen_path().with_suffix(".tmp")
        tmp.write_text(json.dumps(seen, indent=2), encoding="utf-8")
        os.replace(tmp, self._seen_path())

    def _run_id(self, branch: Branch) -> str:
        stamp = time.strftime("%Y%m%dT%H%M%S", time.gmtime(self.d.clock()))
        slug = branch.name[len(self.cfg.repo.branch_prefix):].replace(".", "-")[:40]
        return f"{stamp}-{slug}-{branch.head[:8]}"

    def _tofu_in(self, wt: Path):
        tofu = self.d.tofu_factory(wt / self.cfg.tofu.dir)
        tofu.prepare()
        return tofu

    def _finish(self, run: Run, status: str, reason: str | None = None) -> Run:
        run.status = status
        if reason:
            run.reasons.append(reason)
        run.finished = self.d.clock()
        run.pid = None
        run.save(self.cfg.runs_dir)
        return run

    def _backup_state(self, run_id: str) -> None:
        src = self.cfg.tofu.state_path
        if not src.exists():
            return
        bdir = src.parent / "backups"
        bdir.mkdir(parents=True, exist_ok=True, mode=0o700)
        dst = bdir / f"{run_id}.tfstate"
        shutil.copy2(src, dst)
        os.chmod(dst, 0o600)
        backups = sorted(bdir.glob("*.tfstate"), key=lambda p: p.stat().st_mtime)
        for old in backups[: max(0, len(backups) - self.cfg.tofu.state_backups)]:
            old.unlink(missing_ok=True)

    # ------------------------------------------------------------ Einstieg

    def run_once(self) -> list[Run]:
        """Alle neuen desired/*-Branches abarbeiten. Für den systemd-Timer."""
        if self.cfg.stop_file.exists():
            log.warning("STOP-Datei vorhanden, nichts zu tun.")
            return []
        try:
            with proc.file_lock(self.cfg.lock_file):
                return self._run_locked()
        except proc.LockBusy:
            log.info("Lock belegt, später erneut.")
            return []

    def _run_locked(self) -> list[Run]:
        self.d.git.ensure_clone()
        self.d.git.fetch()
        seen = self._seen()
        results = []
        for br in self.d.git.desired_branches():
            if f"{br.name}@{br.head}" in seen:
                continue
            if self.cfg.stop_file.exists():
                break
            run = self.process(br)
            self._mark_seen(br, run.run_id)
            results.append(run)
            if run.status == "rollback_failed":
                break
        return results

    # ------------------------------------------------------------ ein Branch

    def process(self, br: Branch) -> Run:
        run = Run(run_id=self._run_id(br), branch=br.name, head=br.head, pid=os.getpid(), started=self.d.clock())
        run.save(self.cfg.runs_dir)
        rdir = self._run_dir(run.run_id)
        wt = rdir / "tree"
        try:
            return self._process(run, br, rdir, wt)
        except Exception as e:
            log.exception("Lauf %s abgebrochen", run.run_id)
            self._notify(f"⚠️ **Fehler im Gate**: {br.name}\n{short_reason(f'{type(e).__name__}: {e}')}")
            return self._finish(run, "error", f"{type(e).__name__}: {e}")
        finally:
            self.d.git.remove_worktree(wt)

    def _process(self, run: Run, br: Branch, rdir: Path, wt: Path) -> Run:
        git = self.d.git
        if not git.valid_name(br.name):
            return self._reject(run, f"Ungültiger Branch-Name {br.name}")

        main_ref = f"origin/{self.cfg.repo.main}"
        run.last_good = git.rev(main_ref)
        bad = git.disallowed_paths(main_ref, br.head)
        if bad:
            return self._reject(run, "Nicht erlaubte Pfade: " + ", ".join(bad[:10]))

        git.worktree(wt, run.last_good)
        try:
            run.merge_commit = git.merge_into(wt, br.head, f"gate: {br.name} ({run.run_id})")
        except GitError as e:
            return self._reject(run, str(e))
        bad_vars = self._check_variables(wt, git.changed_paths(main_ref, br.head))
        if bad_vars:
            return self._reject(run, bad_vars)

        tofu = self._tofu_in(wt)
        r = tofu.init()
        if not r.ok:
            return self._reject(run, f"tofu init fehlgeschlagen:\n{r.tail(8)}")
        planfile = rdir / "plan.bin"
        r = tofu.plan(planfile)
        if not r.ok:
            return self._reject(run, f"tofu plan fehlgeschlagen:\n{r.tail(8)}")
        plan_json = tofu.show_json(planfile)
        plan_path = rdir / "plan.json"
        plan_path.write_text(json.dumps(plan_json), encoding="utf-8")
        os.chmod(plan_path, 0o600)
        run.plan_hash = planlib.file_hash(planfile)

        dec = classify(plan_json, self.d.policy)
        run.level = dec.level
        run.summary = (self.d.hooks.text("summary", run.run_id, plan_json=plan_path, repo_dir=wt)
                       or planlib.summarize(dec.changes))
        run.reasons += dec.reasons
        run.save(self.cfg.runs_dir)

        if dec.level == "reject":
            return self._reject(run, None)

        if not dec.changes:
            git.push_main(run.merge_commit)
            git.delete_branch(br.name)
            self._notify(f"☑️ **Ohne Änderung übernommen**: {br.name}")
            return self._finish(run, "noop")

        snap_before = None
        if self.d.hooks.configured("snapshot"):
            snap_before = rdir / "snapshot-before"
            hr = self.d.hooks.snapshot(run.run_id, snap_before)
            if not hr.ok:
                return self._reject(run, "Snapshot vor dem Apply fehlgeschlagen: " + "; ".join(hr.messages()))

        hr = self.d.hooks.run("pre_apply", run.run_id, plan_json=plan_path, repo_dir=wt,
                              snapshot_before=snap_before)
        if not hr.ok:
            return self._reject(run, "Invarianten verletzt: " + "; ".join(hr.messages()))

        if dec.level == "approval":
            if not self.d.approver:
                return self._reject(run, "Freigabe nötig, aber kein Freigabekanal konfiguriert")
            link = self.cfg.repo.commit_url.format(sha=br.head) if self.cfg.repo.commit_url else None
            res = self.d.approver.request(
                plan_hash=run.plan_hash, summary=f"{run.summary}\n\nBranch {br.name}",
                agent_reason=git.message(br.head), link=link,
                timeout_s=self.cfg.approval_timeout_minutes * 60,
            )
            if not getattr(res, "approved", False):
                why = {"declined": "abgelehnt", "timeout": "keine Antwort"}.get(getattr(res, "reason", ""), "")
                self._notify(f"🚫 **Nicht freigegeben**: {br.name}" + (f" ({why})" if why else ""))
                return self._finish(run, "declined", getattr(res, "reason", None))

        return self._apply(run, br, rdir, wt, tofu, planfile, plan_path, snap_before)

    def _check_variables(self, wt: Path, paths: list[str]) -> str | None:
        """Agenten dürfen nur freigegebene Variablen setzen (nicht z. B. Passphrasen)."""
        allowed = self.cfg.repo.allowed_variables
        if allowed is None:
            return None
        for rel in paths:
            if not rel.endswith(".tfvars.json"):
                continue
            path = wt / rel
            if not path.exists():
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                return f"{rel}: kein gültiges JSON ({type(e).__name__})"
            if not isinstance(data, dict):
                return f"{rel}: Objekt erwartet"
            extra = sorted(set(data) - set(allowed))
            if extra:
                return f"{rel}: Variablen nicht erlaubt: {', '.join(extra)}"
        return None

    def _reject(self, run: Run, reason: str | None) -> Run:
        self._finish(run, "rejected", reason)
        why = short_reason(run.reasons[-1] if run.reasons else "") or "ohne Grund"
        self._notify(f"❌ **Abgelehnt**: {run.branch}\n{why}")
        return run

    # ------------------------------------------------------------ Apply

    def _apply(self, run: Run, br: Branch, rdir: Path, wt: Path, tofu, planfile: Path,
               plan_path: Path, snap_before: Path | None) -> Run:
        self._backup_state(run.run_id)
        run.status = "applying"
        run.pid = os.getpid()
        run.save(self.cfg.runs_dir)
        self.d.deadman.schedule(run.run_id)

        if planlib.file_hash(planfile) != run.plan_hash:
            self.d.deadman.cancel(run.run_id)
            return self._reject(run, "Plan-Datei hat sich seit der Prüfung geändert")

        r = tofu.apply(planfile)
        problem = None if r.ok else f"tofu apply fehlgeschlagen:\n{r.tail(8)}"
        if not problem:
            problem = self._health(run, wt, tofu, plan_path, snap_before, rdir)

        if problem:
            run.reasons.append(problem)
            run.save(self.cfg.runs_dir)
            return self._rollback_locked(run, cause=problem)

        self.d.deadman.cancel(run.run_id)
        try:
            self._push_merge(run, br, wt)
        except GitError as e:
            # Änderung ist live und geprüft, nur der Merge fehlt. Kein Rollback.
            self._notify(f"⚠️ **Angewendet, aber nicht gemergt**: {br.name}\n{short_reason(str(e))}")
            return self._finish(run, "applied_unmerged", str(e))
        self._notify(f"✅ **Angewendet**: {br.name}\n{run.summary}")
        return self._finish(run, "applied")

    def _health(self, run: Run, wt: Path, tofu, plan_path: Path, snap_before: Path | None,
                rdir: Path) -> str | None:
        r = tofu.plan_detailed()
        if r.rc != 0:
            return f"Plan nach dem Apply nicht leer (rc={r.rc}):\n{r.tail(8)}"
        snap_after = None
        if self.d.hooks.configured("snapshot"):
            snap_after = rdir / "snapshot-after"
            hr = self.d.hooks.snapshot(run.run_id, snap_after)
            if not hr.ok:
                return "Snapshot nach dem Apply fehlgeschlagen: " + "; ".join(hr.messages())
        hr = self.d.hooks.run("post_apply", run.run_id, plan_json=plan_path, repo_dir=wt,
                              snapshot_before=snap_before, snapshot_after=snap_after)
        if not hr.ok:
            return "Health-Check fehlgeschlagen: " + "; ".join(hr.messages())
        return None

    def _push_merge(self, run: Run, br: Branch, wt: Path) -> None:
        git = self.d.git
        try:
            git.push_main(run.merge_commit)
        except GitError:
            # main hat sich bewegt (z. B. Snapshot-Commit): neu mergen und erneut pushen.
            git.fetch()
            git.checkout(wt, git.rev(f"origin/{self.cfg.repo.main}"))
            run.merge_commit = git.merge_into(wt, br.head, f"gate: {br.name} ({run.run_id})")
            git.push_main(run.merge_commit)
        git.delete_branch(br.name)

    # ------------------------------------------------------------ Rollback

    def rollback(self, run_id: str) -> Run:
        """Einstieg für Dead-Man-Timer und Hand: hängenden Lauf beenden, zurückrollen."""
        run = Run.load(self.cfg.runs_dir, run_id)
        if run.status not in ("applying", "rolling_back"):
            log.info("Lauf %s hat Status %s, kein Rollback nötig.", run_id, run.status)
            return run
        if run.pid and proc.alive(run.pid):
            log.warning("Lauf %s hängt (pid %s), wird beendet.", run_id, run.pid)
            proc.terminate(run.pid)
        with proc.file_lock(self.cfg.lock_file, wait=120):
            return self._rollback_locked(run, cause="Dead-Man-Timer abgelaufen")

    def _rollback_locked(self, run: Run, cause: str) -> Run:
        run.status = "rolling_back"
        run.pid = os.getpid()
        run.save(self.cfg.runs_dir)
        rdir = self._run_dir(run.run_id)
        wt = rdir / "rollback-tree"
        try:
            problem = self._do_rollback(run, rdir, wt)
        except Exception as e:
            log.exception("Rollback %s abgebrochen", run.run_id)
            problem = f"{type(e).__name__}: {e}"
        finally:
            self.d.git.remove_worktree(wt)
        self.d.deadman.cancel(run.run_id)
        if problem:
            self.cfg.stop_file.parent.mkdir(parents=True, exist_ok=True)
            self.cfg.stop_file.write_text(f"Rollback {run.run_id} fehlgeschlagen: {problem}\n", encoding="utf-8")
            self._notify(f"🛑 **Rollback fehlgeschlagen, Gate gestoppt**: {run.branch}\n"
                         f"Grund: {short_reason(cause)}\nRollback: {short_reason(problem)}")
            return self._finish(run, "rollback_failed", problem)
        self._notify(f"↩️ **Zurückgerollt**: {run.branch}\nGrund: {short_reason(cause)}")
        return self._finish(run, "rolled_back")

    def _do_rollback(self, run: Run, rdir: Path, wt: Path) -> str | None:
        if not run.last_good:
            return "kein last-good-Commit bekannt"
        self.d.git.worktree(wt, run.last_good)
        tofu = self._tofu_in(wt)
        r = tofu.init()
        if not r.ok:
            return f"tofu init fehlgeschlagen:\n{r.tail(8)}"
        planfile = rdir / "rollback.bin"
        r = tofu.plan(planfile)
        if not r.ok:
            return f"tofu plan fehlgeschlagen:\n{r.tail(8)}"
        plan_json = tofu.show_json(planfile)
        dec: Decision = classify(plan_json, self.d.policy, rollback=True)
        if dec.level == "reject":
            return "Rollback-Plan verletzt forbidden: " + "; ".join(dec.reasons)
        r = tofu.apply(planfile)
        if not r.ok:
            return f"tofu apply fehlgeschlagen:\n{r.tail(8)}"
        r = tofu.plan_detailed()
        if r.rc != 0:
            return f"Plan nach dem Rollback nicht leer (rc={r.rc})"
        return self._check_rollback(run, rdir, wt)

    def _check_rollback(self, run: Run, rdir: Path, wt: Path) -> str | None:
        """Frischen Snapshot mit dem Stand vor dem Apply vergleichen.

        Ein leerer Plan reicht nicht: Behandelt der Provider null als "nicht anfassen",
        bleibt ein gerade gesetztes Feld nach dem Rollback stehen.
        """
        if not self.d.hooks.configured("post_rollback"):
            return None
        snap_before = snap_after = None
        if self.d.hooks.configured("snapshot"):
            snap_before = rdir / "snapshot-before"
            if not snap_before.is_dir():
                return "Snapshot vor dem Apply fehlt, Vergleich nach dem Rollback nicht möglich"
            snap_after = rdir / "snapshot-after-rollback"
            shutil.rmtree(snap_after, ignore_errors=True)  # Rest eines abgebrochenen Rollbacks
            hr = self.d.hooks.snapshot(run.run_id, snap_after)
            if not hr.ok:
                return "Snapshot nach dem Rollback fehlgeschlagen: " + "; ".join(hr.messages())
        # Nach dem Rollback ist keine Änderung erwartet, daher ein leerer Plan.
        plan_path = rdir / "rollback-check.json"
        plan_path.write_text(json.dumps({"format_version": "1.2", "resource_changes": []}), encoding="utf-8")
        os.chmod(plan_path, 0o600)
        hr = self.d.hooks.run("post_rollback", run.run_id, plan_json=plan_path, repo_dir=wt,
                              snapshot_before=snap_before, snapshot_after=snap_after)
        if not hr.ok:
            return "Stand nach dem Rollback weicht ab: " + "; ".join(hr.messages())
        return None
