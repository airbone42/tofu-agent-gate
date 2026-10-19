"""Externe Hooks: Snapshot, Invarianten, Health-Checks."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from . import proc
from .config import Config, load_env_file


@dataclass
class HookResult:
    ok: bool
    violations: list[dict] = field(default_factory=list)
    error: str | None = None

    def messages(self) -> list[str]:
        msgs = [f"{v.get('id', '?')}: {v.get('message', '')}" for v in self.violations]
        if self.error:
            msgs.append(self.error)
        return msgs


class Hooks:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.env = proc.base_env(load_env_file(cfg.hooks_env_file))

    def configured(self, phase: str) -> bool:
        return bool(self.cfg.hooks.get(phase))

    def run(self, phase: str, run_id: str, **paths: Path | None) -> HookResult:
        argv = self.cfg.hooks.get(phase)
        if not argv:
            return HookResult(ok=True)
        env = dict(self.env, GATE_RUN_ID=run_id, GATE_PHASE=phase)
        for key, value in paths.items():
            if value is not None:
                env[f"GATE_{key.upper()}"] = str(value)
        r = proc.run(argv, env=env, timeout=self.cfg.hook_timeout)
        if phase == "snapshot":
            return HookResult(ok=r.ok, error=None if r.ok else f"Snapshot-Hook rc={r.rc}: {r.tail(3)}")
        try:
            data = json.loads(r.out) if r.out.strip() else {}
        except json.JSONDecodeError:
            data = {}
        violations = [v for v in data.get("violations") or [] if isinstance(v, dict)]
        if r.rc == 0 and data.get("ok", True):
            return HookResult(ok=True, violations=violations)
        if r.rc == 1:
            return HookResult(ok=False, violations=violations or [{"id": phase, "message": "Verstoß ohne Details"}])
        return HookResult(ok=False, violations=violations, error=f"Hook {phase} rc={r.rc}: {r.tail(3)}")

    def snapshot(self, run_id: str, out: Path) -> HookResult:
        out.mkdir(parents=True, exist_ok=True, mode=0o700)
        return self.run("snapshot", run_id, snapshot_out=out)
