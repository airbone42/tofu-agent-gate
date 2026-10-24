"""Freigabe per Telegram-Inline-Buttons.

Eine Freigabe ist an einen Plan-Hash gebunden, zählt genau einmal und läuft ab.
Anfragen und der getUpdates-Offset liegen als JSON-Dateien in store_dir, damit
Replay-Schutz und Ablauf auch über Neustarts greifen.

Mit delegate=True (Stufe review) entscheidet zuerst der beauftragte Prüfer (delegate.py). Nur wenn er
eskaliert oder nicht antwortet, geht die Anfrage an Telegram, mit seinem Hinweis in der Nachricht.
"""

from __future__ import annotations

import html
import json
import logging
import os
import re
import secrets
import tempfile
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .redact import make_redactor
from .telegram import TelegramApi, TelegramError

log = logging.getLogger(__name__)

MAX_TEXT = 4096
MAX_REASON = 800
HASH_SHOWN = 12
REASON_LABEL = "Begründung des Agenten (ungeprüft):"
MAX_REASON_LINE = 300
NOTIFY_RETRY_DELAYS = (5.0, 15.0, 40.0, 60.0)  # Sekunden zwischen den Versuchen von notify
INVALID_HINT = "Nicht gültig"

# Gründe in ApprovalResult.reason
ACCEPTED = "accepted"
DECLINED = "declined"
TIMEOUT = "timeout"
SEND_FAILED = "send_failed"
DELEGATED = "delegated"            # vom Prüfer freigegeben
DELEGATE_DENIED = "delegate_denied"

_ID_RE = re.compile(r"[0-9a-f]{16}")
_CALLBACK_RE = re.compile(r"([0-9a-f]{16}):([ad])")
_NO_BUTTONS = {"inline_keyboard": []}


@dataclass(frozen=True)
class ApprovalResult:
    approved: bool
    reason: str
    request_id: str
    note: str = ""  # Begründung des Prüfers bei delegated / delegate_denied


def tg_len(text: str) -> int:
    """Länge wie Telegram sie zählt (UTF-16-Codeeinheiten)."""
    return len(text.encode("utf-16-le")) // 2


def cut(text: str, limit: int, marker: str = "…") -> str:
    """Auf limit (UTF-16) kürzen, mit Markierung am Ende."""
    if tg_len(text) <= limit:
        return text
    budget = limit - tg_len(marker)
    if budget < 0:
        return ""
    out: list[str] = []
    used = 0
    for ch in text:
        width = 2 if ord(ch) > 0xFFFF else 1
        if used + width > budget:
            break
        out.append(ch)
        used += width
    return "".join(out).rstrip() + marker


def esc(text: str) -> str:
    """HTML für Telegram maskieren. Danach wird nur **x** zu Fettdruck."""
    return html.escape(text, quote=False)


def light_markup(text: str) -> str:
    """Klartext maskieren, **x** in <b>x</b> wandeln. Erzeugt nie Links oder andere Tags."""
    out = esc(text)
    return re.sub(r"\*\*([^*\n]{1,200})\*\*", r"<b>\1</b>", out)


def _atomic_write_json(path: Path, data: Any) -> None:
    """JSON atomar schreiben (tmp + os.replace), Modus 600."""
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, sort_keys=True)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _same_int(value: Any, expected: int) -> bool:
    return type(value) is int and value == expected


class Approver:
    """Freigabe-Anfragen an den Owner, blockierend mit Long Polling."""

    def __init__(
        self,
        api: TelegramApi,
        owner_user_id: int,
        owner_chat_id: int,
        store_dir: str | Path,
        redact: Callable[[str], str] | None = None,
        clock: Callable[[], float] = time.time,
        poll_timeout: int = 50,
        sleep: Callable[[float], None] = time.sleep,
        max_backoff: float = 60,
        delegate: Callable[[dict], Any] | None = None,
    ) -> None:
        self.api = api
        self.owner_user_id = int(owner_user_id)
        self.owner_chat_id = int(owner_chat_id)
        self.store_dir = Path(store_dir)
        self.redact = redact or make_redactor()
        self.clock = clock
        self.sleep = sleep
        self.poll_timeout = max(1, int(poll_timeout))
        self.max_backoff = max_backoff
        self.delegate = delegate
        self._requests_dir = self.store_dir / "requests"
        self._offset_path = self.store_dir / "offset.json"
        self.store_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._requests_dir.mkdir(mode=0o700, exist_ok=True)

    # ---------- Store ----------

    def _record_path(self, request_id: str) -> Path:
        if not _ID_RE.fullmatch(request_id):
            raise ValueError("ungültige request_id")
        return self._requests_dir / f"{request_id}.json"

    def load_record(self, request_id: str) -> dict[str, Any] | None:
        """Gespeicherte Anfrage lesen, None wenn fehlend oder kaputt."""
        try:
            data = json.loads(self._record_path(request_id).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        return data if isinstance(data, dict) else None

    def _save_record(self, record: dict[str, Any]) -> None:
        _atomic_write_json(self._record_path(record["request_id"]), record)

    def _load_offset(self) -> int | None:
        try:
            data = json.loads(self._offset_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        offset = data.get("offset") if isinstance(data, dict) else None
        return offset if type(offset) is int else None

    def _save_offset(self, offset: int | None) -> None:
        if offset is None:
            return
        try:
            _atomic_write_json(self._offset_path, {"offset": offset})
        except OSError as exc:
            log.warning("Offset nicht gespeichert: %s", self.redact(str(exc)))

    def _new_request_id(self) -> str:
        for _ in range(8):
            rid = secrets.token_hex(8)
            if not self._record_path(rid).exists():
                return rid
        raise RuntimeError("keine freie request_id gefunden")

    # ---------- Ausgehendes, immer redigiert ----------

    def _out(self, text: str) -> str:
        # text ist bereits HTML (aus compose oder notify). Kürzen nur als letzte Sicherung.
        return text if tg_len(text) <= MAX_TEXT else cut(text, MAX_TEXT)

    def _send(self, text: str, reply_markup: dict | None = None) -> Any:
        return self.api.call(
            "sendMessage",
            chat_id=self.owner_chat_id,
            text=self._out(text),
            parse_mode="HTML",
            reply_markup=reply_markup,
            link_preview_options={"is_disabled": True},
        )

    def _edit(self, message_id: Any, text: str) -> None:
        if type(message_id) is not int:
            return
        try:
            self.api.call(
                "editMessageText",
                chat_id=self.owner_chat_id,
                message_id=message_id,
                text=self._out(text),
                parse_mode="HTML",
                reply_markup=_NO_BUTTONS,
                link_preview_options={"is_disabled": True},
            )
        except (TelegramError, OSError) as exc:
            log.warning("editMessageText fehlgeschlagen: %s", self.redact(str(exc)))

    def _answer(self, callback_query_id: Any, text: str) -> None:
        if not isinstance(callback_query_id, str):
            return
        try:
            self.api.call(
                "answerCallbackQuery",
                callback_query_id=callback_query_id,
                text=cut(self.redact(text), 200),
            )
        except (TelegramError, OSError) as exc:
            log.warning("answerCallbackQuery fehlgeschlagen: %s", self.redact(str(exc)))

    def notify(self, text: str) -> bool:
        """Meldung an den Owner-Chat. Klartext, **x** wird fett. False bei Fehler, kein Absturz.

        Übertragungsfehler, 429 und 5xx werden nach NOTIFY_RETRY_DELAYS wiederholt (zusammen
        knapp 2 min): Ein kurzer DNS-Aussetzer in CT 109 hat am 23.10.2026 die Meldung zu einem
        fehlgeschlagenen Rollback verschluckt."""
        body = light_markup(cut(self.redact(text), MAX_TEXT - 200))
        for attempt in range(len(NOTIFY_RETRY_DELAYS) + 1):
            try:
                self._send(body)
                return True
            except (TelegramError, OSError) as exc:
                log.warning("notify fehlgeschlagen: %s", self.redact(str(exc)))
                code = getattr(exc, "error_code", None)
                if isinstance(code, int) and 400 <= code < 500 and code != 429:
                    return False
                if attempt == len(NOTIFY_RETRY_DELAYS):
                    return False
                wait = NOTIFY_RETRY_DELAYS[attempt]
                retry_after = getattr(exc, "retry_after", None)
                if isinstance(retry_after, (int, float)) and retry_after > 0:
                    wait = min(float(retry_after), self.max_backoff)
                self.sleep(wait)
        return False

    # ---------- Text ----------

    def compose(
        self,
        header: str,
        *,
        request_id: str,
        plan_hash: str,
        summary: str,
        agent_reason: str | None = None,
        link: str | None = None,
        info: Iterable[str] = (),
    ) -> str:
        """Lesbare HTML-Nachricht, höchstens MAX_TEXT. Alles Dynamische redigiert und maskiert.

        summary ist Klartext, **x** wird fett. Von agent_reason zählt nur die erste Zeile.
        """
        r = self.redact
        parts = [f"<b>{esc(header)}</b>"]
        body = cut(r(summary or "").strip(), MAX_TEXT - 1200)
        if body:
            parts.append(light_markup(body))
        if agent_reason:
            first = next((ln.strip() for ln in r(agent_reason).splitlines() if ln.strip()), "")
            if first:
                parts.append(f"<i>{esc(REASON_LABEL)}</i>\n{esc(cut(first, MAX_REASON_LINE))}")
        foot = [f"Plan {esc(plan_hash[:8])}", *[esc(i) for i in info]]
        link_text = r(link).strip() if link else ""
        if link_text.startswith(("http://", "https://")):
            foot.append(f'<a href="{html.escape(link_text, quote=True)}">Commit</a>')
        parts.append("<i>" + " · ".join(foot) + "</i>")
        text = "\n\n".join(parts)
        return text if tg_len(text) <= MAX_TEXT else cut(text, MAX_TEXT)

    # ---------- Freigabe ----------

    def request(
        self,
        *,
        plan_hash: str,
        summary: str,
        agent_reason: str | None = None,
        link: str | None = None,
        timeout_s: float = 1800,
        delegate: bool = False,
    ) -> ApprovalResult:
        """Freigabe anfragen und blockierend auf Accept, Decline oder Ablauf warten.

        delegate: erst den beauftragten Prüfer fragen (Stufe review), ohne Prüfer wie bisher."""
        if not isinstance(plan_hash, str) or not plan_hash:
            raise ValueError("plan_hash fehlt")
        rid = self._new_request_id()
        created = self.clock()
        expires = created + float(timeout_s)
        record: dict[str, Any] = {
            "request_id": rid,
            "plan_hash": plan_hash,
            "chat_id": self.owner_chat_id,
            "message_id": None,
            "status": "sending",
            "created": created,
            "expires": expires,
        }
        # ID reservieren, bevor die Nachricht rausgeht
        self._save_record(record)

        if delegate and self.delegate is not None:
            record["status"] = "delegated"
            self._save_record(record)
            verdict = self.delegate({"request_id": rid, "plan_hash": plan_hash, "summary": self.redact(summary or ""),
                                     "agent_reason": self.redact(agent_reason or ""), "link": link,
                                     "timeout_s": timeout_s})
            decision = getattr(verdict, "decision", None)
            by = getattr(verdict, "by", "") or "Prüfer"
            note = getattr(verdict, "note", "") or ""
            if decision in ("approve", "deny"):
                approved = decision == "approve"
                record.update(status="approved" if approved else "declined", decided_at=self.clock(),
                              decided_by=f"delegate:{by}", note=note)
                self._save_record(record)
                return ApprovalResult(approved, DELEGATED if approved else DELEGATE_DENIED, rid, note)
            record["status"] = "sending"
            self._save_record(record)
            summary = f"{summary}\n\n🤖 {by} gibt das an dich weiter" + (f": {note}" if note else "")

        content = {"request_id": rid, "plan_hash": plan_hash, "summary": summary,
                   "agent_reason": agent_reason, "link": link}
        minutes = max(1, round(float(timeout_s) / 60))
        text = self.compose("Freigabe nötig", info=[f"gültig {minutes} min"], **content)
        markup = {"inline_keyboard": [[
            {"text": "Accept", "callback_data": f"{rid}:a"},
            {"text": "Decline", "callback_data": f"{rid}:d"},
        ]]}

        message = self._send_with_retry(text, markup, expires)
        message_id = message.get("message_id") if isinstance(message, dict) else None
        if type(message_id) is not int:
            record.update(status="send_failed", decided_at=self.clock())
            self._save_record(record)
            return ApprovalResult(False, SEND_FAILED, rid)

        record.update(status="open", message_id=message_id)
        self._save_record(record)

        decision, last_error = self._poll(rid, plan_hash)
        if decision is None:
            current = self.load_record(rid) or record
            if current.get("status") == "open":
                current.update(status="expired", decided_at=self.clock())
                if last_error:
                    current["last_error"] = last_error
                try:
                    self._save_record(current)
                except OSError as exc:
                    log.warning("Anfrage nicht gespeichert: %s", self.redact(str(exc)))
            self._edit(message_id, self.compose("Abgelaufen, nicht freigegeben", **content))
            return ApprovalResult(False, TIMEOUT, rid)

        approved = decision == "a"
        header = "Freigegeben" if approved else "Abgelehnt"
        self._edit(message_id, self.compose(header, **content))
        return ApprovalResult(approved, ACCEPTED if approved else DECLINED, rid)

    def _send_with_retry(self, text: str, markup: dict, expires: float, attempts: int = 3) -> Any:
        delay = 1.0
        for attempt in range(attempts):
            try:
                return self._send(text, markup)
            except (TelegramError, OSError) as exc:
                log.warning("sendMessage fehlgeschlagen: %s", self.redact(str(exc)))
                code = getattr(exc, "error_code", None)
                # Client-Fehler (außer 429) wiederholen bringt nichts
                if isinstance(code, int) and 400 <= code < 500 and code != 429:
                    return None
                remaining = expires - self.clock()
                if attempt == attempts - 1 or remaining <= 0:
                    return None
                self.sleep(min(delay, remaining))
                delay *= 2
        return None

    def _poll(self, rid: str, plan_hash: str) -> tuple[str | None, str | None]:
        """getUpdates bis Entscheidung oder Ablauf. Liefert ("a"|"d"|None, letzter Fehler)."""
        record = self.load_record(rid) or {}
        expires = float(record.get("expires", 0))
        offset = self._load_offset()
        backoff = 1.0
        last_error: str | None = None
        while True:
            remaining = expires - self.clock()
            if remaining <= 0:
                return None, last_error
            timeout = max(1, int(min(self.poll_timeout, remaining)))
            try:
                updates = self.api.call(
                    "getUpdates", offset=offset, timeout=timeout, allowed_updates=["callback_query"]
                )
                if not isinstance(updates, list):
                    raise TelegramError("getUpdates: ungültige Antwort", method="getUpdates")
            except (TelegramError, OSError) as exc:
                last_error = self.redact(str(exc))
                log.warning("getUpdates fehlgeschlagen: %s", last_error)
                wait = backoff
                retry_after = getattr(exc, "retry_after", None)
                if isinstance(retry_after, (int, float)) and retry_after > 0:
                    wait = float(retry_after)
                remaining = expires - self.clock()
                if remaining > 0:
                    self.sleep(min(wait, remaining))
                backoff = min(backoff * 2, self.max_backoff)
                continue
            backoff = 1.0

            decision: str | None = None
            for update in updates:
                if not isinstance(update, dict):
                    continue
                uid = update.get("update_id")
                if type(uid) is int and (offset is None or uid >= offset):
                    offset = uid + 1
                callback = update.get("callback_query")
                if isinstance(callback, dict):
                    # weitere Klicks im selben Stapel laufen in die Prüfung und scheitern dort
                    choice = self._handle_callback(callback, rid, plan_hash)
                    if choice is not None and decision is None:
                        decision = choice
                # andere Update-Arten: ignorieren, Offset zählt trotzdem weiter
            if updates:
                self._save_offset(offset)
            if decision is not None:
                return decision, None

    def _check_click(self, callback: dict, rid: str, plan_hash: str) -> str | None:
        """Prüft einen Klick gegen die offene Anfrage. Liefert "a", "d" oder None."""
        data = callback.get("data")
        if not isinstance(data, str):
            return None
        m = _CALLBACK_RE.fullmatch(data)
        if not m or m.group(1) != rid:
            return None
        sender = callback.get("from") if isinstance(callback.get("from"), dict) else {}
        message = callback.get("message") if isinstance(callback.get("message"), dict) else {}
        chat = message.get("chat") if isinstance(message.get("chat"), dict) else {}
        if not _same_int(sender.get("id"), self.owner_user_id):
            return None
        if not _same_int(chat.get("id"), self.owner_chat_id):
            return None
        record = self.load_record(rid)
        if record is None or record.get("status") != "open":
            return None
        stored_id = record.get("message_id")
        if type(stored_id) is not int or not _same_int(message.get("message_id"), stored_id):
            return None
        if not _same_int(record.get("chat_id"), self.owner_chat_id):
            return None
        expires = record.get("expires")
        if not isinstance(expires, (int, float)) or not self.clock() < expires:
            return None
        if record.get("plan_hash") != plan_hash:
            return None
        return m.group(2)

    def _handle_callback(self, callback: dict, rid: str, plan_hash: str) -> str | None:
        cq_id = callback.get("id")
        choice = self._check_click(callback, rid, plan_hash)
        if choice is None:
            self._answer(cq_id, INVALID_HINT)
            return None
        record = self.load_record(rid) or {}
        record.update(
            status="approved" if choice == "a" else "declined",
            decided_at=self.clock(),
            decided_by=self.owner_user_id,
        )
        try:
            # erst speichern, dann bestätigen: ohne gespeicherte Entscheidung kein Ergebnis
            self._save_record(record)
        except OSError as exc:
            log.warning("Entscheidung nicht gespeichert: %s", self.redact(str(exc)))
            self._answer(cq_id, INVALID_HINT)
            return None
        self._answer(cq_id, "Angenommen" if choice == "a" else "Abgelehnt")
        return choice
