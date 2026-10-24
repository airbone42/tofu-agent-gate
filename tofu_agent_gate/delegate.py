"""Beauftragter Prüfer für die Stufe review (approval.delegate_command in gate.yaml).

Der Befehl bekommt die Anfrage als JSON auf stdin:

  {"request_id": "...", "plan_hash": "...", "summary": "...", "agent_reason": "...", "link": "...",
   "timeout_s": 1800}

und schreibt seine Entscheidung als JSON auf stdout (die letzte Zeile, die ein JSON-Objekt ist, zählt):

  {"decision": "approve" | "deny" | "escalate", "by": "hermes", "note": "ein Satz"}

approve gibt frei, deny lehnt ab, escalate (oder jede andere Antwort, Exit ungleich 0, Zeitüberschreitung)
lässt das Gate wie bei approval per Telegram fragen. Der Befehl läuft beim Runner, nie aus dem Repo.
"""

from __future__ import annotations

import json
import logging
import subprocess
from collections.abc import Callable
from dataclasses import dataclass

log = logging.getLogger(__name__)

APPROVE = "approve"
DENY = "deny"
ESCALATE = "escalate"
DECISIONS = (APPROVE, DENY, ESCALATE)
MAX_NOTE = 500
MAX_BY = 40
SLACK_S = 30  # Sekunden über timeout_s hinaus, bevor der Befehl abgebrochen wird


@dataclass(frozen=True)
class Verdict:
    decision: str
    by: str = ""
    note: str = ""


def _clean(text: object, limit: int) -> str:
    out = "".join(ch for ch in str(text or "") if ch == "\n" or ch >= " ")
    return out.strip()[:limit]


def parse(stdout: str) -> Verdict:
    """Letzte JSON-Zeile auswerten. Alles Unklare ist escalate."""
    for line in reversed((stdout or "").splitlines()):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            data = json.loads(line)
        except ValueError:
            continue
        if isinstance(data, dict) and data.get("decision") in DECISIONS:
            return Verdict(data["decision"], _clean(data.get("by"), MAX_BY), _clean(data.get("note"), MAX_NOTE))
        break
    return Verdict(ESCALATE, note="Prüfer ohne gültige Entscheidung")


class CommandDelegate:
    def __init__(self, command: list[str], redact: Callable[[str], str] | None = None,
                 run: Callable[..., subprocess.CompletedProcess] = subprocess.run) -> None:
        if not command:
            raise ValueError("delegate_command ist leer")
        self.command = list(command)
        self.redact = redact or (lambda s: s)
        self.run = run

    def __call__(self, request: dict) -> Verdict:
        timeout = float(request.get("timeout_s") or 1800) + SLACK_S
        try:
            res = self.run(self.command, input=json.dumps(request, ensure_ascii=False), capture_output=True,
                           text=True, timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            log.warning("Prüfer nach %.0f s abgebrochen", timeout)
            return Verdict(ESCALATE, note="Prüfer hat nicht rechtzeitig entschieden")
        except OSError as exc:
            log.warning("Prüfer nicht startbar: %s", self.redact(str(exc)))
            return Verdict(ESCALATE, note="Prüfer nicht erreichbar")
        if res.returncode != 0:
            log.warning("Prüfer Exit %s: %s", res.returncode, self.redact((res.stderr or "").strip()[-300:]))
            return Verdict(ESCALATE, note=f"Prüfer Exit {res.returncode}")
        return parse(res.stdout)
