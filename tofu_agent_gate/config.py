"""gate.yaml laden. Alle Pfade sind Defaults und per Datei überschreibbar."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

DEFAULT_CONFIG = "/etc/tofu-agent-gate/gate.yaml"
HOOK_PHASES = ("snapshot", "pre_apply", "post_apply", "post_rollback", "recover", "summary")


class ConfigError(ValueError):
    pass


@dataclass
class RepoConfig:
    url: str
    workdir: Path
    main: str = "main"
    branch_prefix: str = "desired/"
    allowed_paths: list[str] = field(default_factory=lambda: ["tofu/*.auto.tfvars.json"])
    commit_url: str | None = None
    ssh_key: Path | None = None
    # Oberste Schlüssel, die *.tfvars.json im Branch setzen dürfen. None = keine Prüfung.
    allowed_variables: list[str] | None = None
    author_name: str = "tofu-agent-gate"
    author_email: str = "gate@localhost"


@dataclass
class TofuConfig:
    binary: str = "/usr/local/bin/tofu"
    dir: str = "tofu"
    env_file: Path | None = None
    cli_config: Path | None = None
    state_path: Path = Path("/var/lib/tofu-agent-gate/tofu/terraform.tfstate")
    state_backups: int = 30
    timeout: int = 1200


@dataclass
class Config:
    state_dir: Path
    stop_file: Path
    lock_file: Path
    repo: RepoConfig
    tofu: TofuConfig
    policy: Path
    telegram_env: Path | None = None
    approval_timeout_minutes: int = 30
    # Stufe review: Befehl, der JSON auf stdin bekommt und eine Entscheidung liefert (delegate.py)
    delegate_command: list[str] = field(default_factory=list)
    # Gesetzt (z. B. "tobias"): auch approval-Anfragen gehen an den Prüfer, der sie dem Owner vorlegt
    delegate_owner: str = ""
    deadman_minutes: int = 10
    deadman_unit_prefix: str = "tofu-agent-gate-rollback"
    hooks: dict[str, list[str]] = field(default_factory=dict)
    hooks_env_file: Path | None = None
    hook_timeout: int = 300
    redaction_extra: str | None = None
    # Arbeitsordner abgeschlossener Läufe (Snapshots, Pläne). Ein UniFi-Snapshot hat ~3700 Dateien,
    # 30 Läufe mit zwei Snapshots füllten am 23.10.2026 die Inodes einer 4-GB-Platte.
    keep_work_dirs: int = 10
    # Vor jedem Branch mindestens so viel Prozent Platz und Inodes frei im state_dir, sonst wartet
    # der Branch. Ein Apply ohne Platz für Snapshot und Rollback endet in rollback_failed. 0 = aus.
    min_free_percent: int = 10
    max_branches_per_run: int = 0  # 0 = alle neuen Branches in einem run-once
    # >0: Bleibt nach max_branches_per_run etwas offen, Lock drain_pause_seconds freigeben und
    # weitermachen, solange der Lauf jünger als drain_minutes ist. 0 = bis zum nächsten run-once.
    drain_minutes: int = 0
    drain_pause_seconds: int = 15
    # Nach einem fehlgeschlagenen Rollback alle wartenden Branches verwerfen. Sie bauen auf einem
    # Stand auf, der so nicht mehr gilt. Neuer Versuch nach dem STOP = neuer Commit.
    discard_pending_on_stop: bool = True
    # recover: je STOP eine Prüfung, eine Nachfrage ohne Antwort frühestens nach so vielen Stunden erneut
    recover_reask_hours: float = 6
    source: Path | None = None

    @property
    def runs_dir(self) -> Path:
        return self.state_dir / "runs"


def _p(v: Any) -> Path | None:
    return Path(v) if v else None


def from_dict(d: dict, source: Path | None = None) -> Config:
    try:
        repo = d["repo"]
        state_dir = Path(d.get("state_dir", "/var/lib/tofu-agent-gate"))
        t = d.get("tofu") or {}
        appr = d.get("approval") or {}
        dm = d.get("deadman") or {}
        hooks = d.get("hooks") or {}
        unknown_hooks = set(hooks) - {*HOOK_PHASES, "env_file", "timeout"}
        if unknown_hooks:
            raise ConfigError(f"Unbekannte Hooks {sorted(unknown_hooks)}")
        author = repo.get("author") or {}
        return Config(
            state_dir=state_dir,
            stop_file=Path(d.get("stop_file", "/etc/tofu-agent-gate/STOP")),
            lock_file=Path(d.get("lock_file", "/run/tofu-agent-gate.lock")),
            repo=RepoConfig(
                url=repo["url"],
                workdir=Path(repo.get("workdir", state_dir / "repo")),
                main=repo.get("main", "main"),
                branch_prefix=repo.get("branch_prefix", "desired/"),
                allowed_paths=list(repo.get("allowed_paths") or ["tofu/*.auto.tfvars.json"]),
                commit_url=repo.get("commit_url"),
                ssh_key=_p(repo.get("ssh_key")),
                allowed_variables=repo.get("allowed_variables"),
                author_name=author.get("name", "tofu-agent-gate"),
                author_email=author.get("email", "gate@localhost"),
            ),
            tofu=TofuConfig(
                binary=t.get("binary", "/usr/local/bin/tofu"),
                dir=t.get("dir", "tofu"),
                env_file=_p(t.get("env_file")),
                cli_config=_p(t.get("cli_config")),
                state_path=Path(t.get("state_path", state_dir / "tofu" / "terraform.tfstate")),
                state_backups=int(t.get("state_backups", 30)),
                timeout=int(t.get("timeout", 1200)),
            ),
            policy=Path(d.get("policy", "/etc/tofu-agent-gate/policy.yaml")),
            telegram_env=_p(appr.get("telegram_env")),
            approval_timeout_minutes=int(appr.get("timeout_minutes", 30)),
            delegate_command=[str(x) for x in appr.get("delegate_command") or []],
            delegate_owner=str(appr.get("delegate_owner") or ""),
            deadman_minutes=int(dm.get("minutes", 10)),
            deadman_unit_prefix=dm.get("unit_prefix", "tofu-agent-gate-rollback"),
            hooks={k: list(v) for k, v in hooks.items() if k in HOOK_PHASES and v},
            hooks_env_file=_p(hooks.get("env_file")),
            hook_timeout=int(hooks.get("timeout", 300)),
            redaction_extra=(d.get("redaction") or {}).get("extra"),
            keep_work_dirs=int(d.get("keep_work_dirs", 10)),
            min_free_percent=int(d.get("min_free_percent", 10)),
            max_branches_per_run=int(d.get("max_branches_per_run", 0)),
            drain_minutes=int(d.get("drain_minutes", 0)),
            drain_pause_seconds=int(d.get("drain_pause_seconds", 15)),
            discard_pending_on_stop=bool(d.get("discard_pending_on_stop", True)),
            recover_reask_hours=float(d.get("recover_reask_hours", 6)),
            source=source,
        )
    except KeyError as e:
        raise ConfigError(f"Pflichtfeld fehlt: {e}") from None


def load(path: str | Path | None = None) -> Config:
    path = Path(path or os.environ.get("GATE_CONFIG") or DEFAULT_CONFIG)
    with open(path, encoding="utf-8") as f:
        return from_dict(yaml.safe_load(f) or {}, source=path)


def load_env_file(path: Path | None) -> dict[str, str]:
    """KEY=VALUE-Datei lesen (Kommentare, optionale Anführungszeichen, export)."""
    if not path:
        return {}
    env = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.removeprefix("export ").partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        env[key.strip()] = value
    return env
