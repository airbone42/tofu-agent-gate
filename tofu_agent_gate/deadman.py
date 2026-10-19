"""Dead-Man-Switch: Rollback-Timer, der auch greift, wenn der Runner hängt."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from . import proc
from .config import Config


class DeadmanError(RuntimeError):
    pass


class Systemd:
    """Rollback per systemd-run einplanen, nach Erfolg abbrechen."""

    def __init__(self, cfg: Config):
        self.cfg = cfg

    def unit(self, run_id: str) -> str:
        return f"{self.cfg.deadman_unit_prefix}-{run_id}"

    def argv(self, run_id: str) -> list[str]:
        argv = [
            "systemd-run", "--quiet", f"--unit={self.unit(run_id)}",
            f"--on-active={self.cfg.deadman_minutes}min", "--timer-property=AccuracySec=1s",
            "--property=Type=oneshot",
        ]
        if self.cfg.source:
            argv.append(f"--setenv=GATE_CONFIG={self.cfg.source}")
        # Der Rollback-Dienst muss denselben Code finden wie der Runner, sonst
        # scheitert er im Ernstfall mit ModuleNotFoundError.
        pkg_root = Path(__file__).resolve().parent.parent
        pythonpath = os.environ.get("PYTHONPATH") or str(pkg_root)
        argv.append(f"--setenv=PYTHONPATH={pythonpath}")
        argv += [sys.executable, "-m", "tofu_agent_gate", "rollback", run_id]
        return argv

    def schedule(self, run_id: str) -> None:
        r = proc.run(self.argv(run_id), env=proc.base_env(), timeout=30)
        if not r.ok:
            raise DeadmanError(f"systemd-run fehlgeschlagen: {r.tail(3)}")

    def cancel(self, run_id: str) -> None:
        unit = self.unit(run_id)
        proc.run(["systemctl", "stop", f"{unit}.timer"], env=proc.base_env(), timeout=30)
        proc.run(["systemctl", "reset-failed", f"{unit}.timer", f"{unit}.service"], env=proc.base_env(), timeout=30)

