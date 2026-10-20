"""Gefälschtes OpenTofu mit einem simulierten Controller (JSON-Datei).

Konfiguration: tofu/*.auto.tfvars.json mit {"dns_records": {key: attrs}}.
Fehler lassen sich über Werte einschleusen:
  value == "FAIL_APPLY"   Apply bricht nach dem Schreiben ab (rc 1)
  value == "SILENT_DRIFT" Controller speichert etwas anderes (Plan danach nicht leer)
  value == "CRASH"        Runner-Prozess stirbt mitten im Apply (BaseException)
Wie beim UniFi-Provider heißt null "nicht anfassen": Der Wert auf dem Controller bleibt.
"""

from __future__ import annotations

import json
from pathlib import Path

from tofu_agent_gate import proc
from tofu_agent_gate.tofu import OVERRIDE_FILE

PROVIDER = "registry.opentofu.org/ubiquiti-community/unifi"


class Crash(BaseException):
    pass


class FakeTofu:
    calls: list[tuple[str, str]] = []

    def __init__(self, workdir: Path, controller: Path):
        self.workdir = Path(workdir)
        self.controller = controller

    def _ctl(self) -> dict:
        return json.loads(self.controller.read_text())

    def _save(self, data: dict) -> None:
        self.controller.write_text(json.dumps(data, indent=2, sort_keys=True))

    def _desired(self) -> dict:
        out = {}
        for f in sorted(self.workdir.glob("*.auto.tfvars.json")):
            for key, attrs in (json.loads(f.read_text()).get("dns_records") or {}).items():
                out[f'unifi_dns_record.this["{key}"]'] = attrs
        return out

    @staticmethod
    def _merge(before: dict | None, after: dict | None) -> dict | None:
        if after is None:
            return None
        out = {k: v for k, v in after.items() if v is not None}
        out.update({k: before[k] for k, v in after.items() if v is None and before and k in before})
        return out

    def _changes(self) -> list[dict]:
        ctl, want = self._ctl(), self._desired()
        changes = []
        for addr in sorted(set(ctl) | set(want)):
            before = ctl.get(addr)
            after = self._merge(before, want.get(addr))
            if before == after:
                continue
            actions = ["create"] if before is None else ["delete"] if after is None else ["update"]
            changes.append({
                "address": addr, "mode": "managed", "type": "unifi_dns_record", "name": "this",
                "provider_name": PROVIDER,
                "change": {"actions": actions, "before": before, "after": after,
                           "after_unknown": {}, "before_sensitive": False, "after_sensitive": False},
            })
        return changes

    def prepare(self) -> None:
        (self.workdir / OVERRIDE_FILE).write_text("# override\n")

    def init(self) -> proc.Result:
        FakeTofu.calls.append(("init", str(self.workdir)))
        ok = (self.workdir / OVERRIDE_FILE).exists()
        return proc.Result(0 if ok else 1, "", "" if ok else "override fehlt")

    def plan(self, out: Path) -> proc.Result:
        FakeTofu.calls.append(("plan", str(self.workdir)))
        Path(out).write_text(json.dumps(self._changes()))
        return proc.Result(0, "", "")

    def show_json(self, planfile: Path) -> dict:
        return {
            "format_version": "1.2",
            "resource_changes": json.loads(Path(planfile).read_text()),
            "configuration": {"provider_config": {"unifi": {"name": "unifi", "full_name": PROVIDER}},
                              "root_module": {}},
        }

    def apply(self, planfile: Path) -> proc.Result:
        FakeTofu.calls.append(("apply", str(self.workdir)))
        ctl = self._ctl()
        for rc in json.loads(Path(planfile).read_text()):
            after = rc["change"]["after"]
            value = (after or {}).get("value")
            if after is None:
                ctl.pop(rc["address"], None)
            elif value == "SILENT_DRIFT":
                ctl[rc["address"]] = dict(after, value="something-else")
            else:
                ctl[rc["address"]] = after
            self._save(ctl)
            if value == "FAIL_APPLY":
                return proc.Result(1, "", "Error: simulated provider failure")
            if value == "CRASH":
                raise Crash("Runner stirbt im Apply")
        return proc.Result(0, "", "")

    def plan_detailed(self) -> proc.Result:
        return proc.Result(2 if self._changes() else 0, "", "")
