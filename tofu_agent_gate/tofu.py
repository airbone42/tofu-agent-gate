"""Aufrufe von OpenTofu. Tests ersetzen die Klasse durch eine Fälschung."""

from __future__ import annotations

import json
from pathlib import Path

from . import proc
from .config import Config, load_env_file

OVERRIDE_FILE = "zz_gate_override.tf"


def override_hcl(state_path: Path) -> str:
    # Backend kommt immer vom Runner. Agenten-HCL kann es so nicht umlenken.
    path = str(state_path).replace("\\", "/")
    return (
        "# Vom tofu-agent-gate geschrieben, nicht committen.\n"
        "terraform {\n"
        f'  backend "local" {{\n    path = "{path}"\n  }}\n'
        "}\n"
    )


class Tofu:
    def __init__(self, cfg: Config, workdir: Path):
        self.cfg = cfg
        self.workdir = Path(workdir)
        extra = load_env_file(cfg.tofu.env_file)
        extra.update({"TF_IN_AUTOMATION": "1", "TF_INPUT": "0"})
        if cfg.tofu.cli_config:
            extra["TF_CLI_CONFIG_FILE"] = str(cfg.tofu.cli_config)
        self.env = proc.base_env(extra)

    def _run(self, *args: str) -> proc.Result:
        return proc.run([self.cfg.tofu.binary, *args], cwd=self.workdir, env=self.env,
                        timeout=self.cfg.tofu.timeout)

    def prepare(self) -> None:
        self.cfg.tofu.state_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        (self.workdir / OVERRIDE_FILE).write_text(override_hcl(self.cfg.tofu.state_path))

    def init(self) -> proc.Result:
        # -lockfile=readonly: Provider-Hashes kommen aus dem committeten Lockfile.
        return self._run("init", "-input=false", "-no-color", "-lockfile=readonly", "-reconfigure")

    def plan(self, out: Path) -> proc.Result:
        return self._run("plan", "-input=false", "-no-color", "-lock-timeout=120s", f"-out={out}")

    def show_json(self, planfile: Path) -> dict:
        r = self._run("show", "-json", "-no-color", str(planfile))
        if not r.ok:
            raise RuntimeError(f"tofu show fehlgeschlagen: {r.tail(5)}")
        return json.loads(r.out)

    def apply(self, planfile: Path) -> proc.Result:
        return self._run("apply", "-input=false", "-no-color", "-lock-timeout=120s", str(planfile))

    def plan_detailed(self) -> proc.Result:
        """Exitcode 0 = keine Änderungen, 2 = Diff, sonst Fehler."""
        return self._run("plan", "-input=false", "-no-color", "-lock-timeout=120s", "-detailed-exitcode")
