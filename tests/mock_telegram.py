"""Fake-Bot-API für Tests: transport-Callable mit Zustand, ohne Netz."""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from typing import Any


class FakeClock:
    """Uhr und Schlaf-Funktion für Tests, schläft nie wirklich."""

    def __init__(self, start: float = 1_700_000_000.0) -> None:
        self.now = float(start)
        self.sleeps: list[float] = []

    def time(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.advance(seconds)

    def advance(self, seconds: float) -> None:
        self.now += max(0.0, float(seconds))


def _tg_len(text: str) -> int:
    return len(text.encode("utf-16-le")) // 2


class MockTelegram:
    """Simuliert sendMessage, editMessageText, answerCallbackQuery und getUpdates.

    script: Liste von Aktionen (Callable[[MockTelegram], None]); jeder getUpdates-
    Aufruf führt zuerst die nächste aus, z. B. um einen Klick einzuspeisen.
    Ohne passende Updates rückt getUpdates die Uhr um den Poll-Timeout vor.
    """

    MAX_CALLS = 10_000

    def __init__(self, clock: FakeClock | None = None, first_message_id: int = 100) -> None:
        self.clock = clock
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.sent: list[dict[str, Any]] = []
        self.edited: list[dict[str, Any]] = []
        self.answered: list[dict[str, Any]] = []
        self.messages: dict[tuple[int, int], dict[str, Any]] = {}
        self.updates: list[dict[str, Any]] = []
        self.script: list[Callable[[MockTelegram], None]] = []
        self.failures: dict[str, list[Any]] = {}
        self.broken: dict[str, Callable[[], Any]] = {}
        self._next_update_id = 5000
        self._next_message_id = first_message_id
        self._next_cq_id = 1

    # ---------- Transport ----------

    def __call__(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if len(self.calls) >= self.MAX_CALLS:
            raise RuntimeError("zu viele Aufrufe, Endlosschleife?")
        params = copy.deepcopy(json.loads(json.dumps(params)))  # muss JSON-fähig sein
        self.calls.append((method, params))
        if method in self.broken:
            return self._fail(self.broken[method]())
        queue = self.failures.get(method)
        if queue:
            return self._fail(queue.pop(0))
        handler = getattr(self, "_m_" + method, None)
        if handler is None:
            return {"ok": False, "error_code": 404, "description": "Not Found"}
        return handler(params)

    @staticmethod
    def _fail(item: Any) -> dict[str, Any]:
        if isinstance(item, BaseException):
            raise item
        return item

    def fail(self, method: str, *items: Any) -> None:
        """Nächste Aufrufe von method scheitern: Exception wird geworfen, dict zurückgegeben."""
        self.failures.setdefault(method, []).extend(items)

    def break_method(self, method: str, factory: Callable[[], Any]) -> None:
        """method scheitert dauerhaft (factory liefert Exception oder Antwort-dict)."""
        self.broken[method] = factory

    # ---------- Methoden ----------

    @staticmethod
    def _ok(result: Any) -> dict[str, Any]:
        return {"ok": True, "result": result}

    @staticmethod
    def _bad(description: str) -> dict[str, Any]:
        return {"ok": False, "error_code": 400, "description": f"Bad Request: {description}"}

    def _m_sendMessage(self, p: dict[str, Any]) -> dict[str, Any]:
        text = p.get("text")
        if type(p.get("chat_id")) is not int:
            return self._bad("chat not found")
        if not isinstance(text, str) or not text:
            return self._bad("message text is empty")
        if _tg_len(text) > 4096:
            return self._bad("message is too long")
        msg_id = self._next_message_id
        self._next_message_id += 1
        msg = {
            "message_id": msg_id,
            "chat": {"id": p["chat_id"], "type": "private"},
            "date": int(self.clock.now) if self.clock else 0,
            "text": text,
        }
        if "reply_markup" in p:
            msg["reply_markup"] = p["reply_markup"]
        self.messages[(p["chat_id"], msg_id)] = msg
        self.sent.append({**msg, "params": p})
        return self._ok(copy.deepcopy(msg))

    def _m_editMessageText(self, p: dict[str, Any]) -> dict[str, Any]:
        key = (p.get("chat_id"), p.get("message_id"))
        if key not in self.messages:
            return self._bad("message to edit not found")
        text = p.get("text")
        if not isinstance(text, str) or not text:
            return self._bad("message text is empty")
        if _tg_len(text) > 4096:
            return self._bad("message is too long")
        msg = self.messages[key]
        msg["text"] = text
        if "reply_markup" in p:
            msg["reply_markup"] = p["reply_markup"]
        else:
            msg.pop("reply_markup", None)
        self.edited.append(dict(p))
        return self._ok(copy.deepcopy(msg))

    def _m_answerCallbackQuery(self, p: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(p.get("callback_query_id"), str):
            return self._bad("query is too old")
        self.answered.append(dict(p))
        return self._ok(True)

    def _m_getUpdates(self, p: dict[str, Any]) -> dict[str, Any]:
        if self.script:
            self.script.pop(0)(self)
        offset = p.get("offset")
        if isinstance(offset, int):
            # wie Telegram: alles unter offset gilt als bestätigt
            self.updates = [u for u in self.updates if u["update_id"] >= offset]
        result = self.updates[:100]
        if not result and self.clock is not None:
            self.clock.advance(p.get("timeout", 0))
        return self._ok(copy.deepcopy(result))

    # ---------- Hilfen für Tests ----------

    def push_update(self, update: dict[str, Any]) -> int:
        update = dict(update)
        if "update_id" not in update:
            update["update_id"] = self._next_update_id
            self._next_update_id += 1
        self.updates.append(update)
        return update["update_id"]

    def push_callback(
        self, data: str, *, from_id: int, chat_id: int, message_id: int, cq_id: str | None = None
    ) -> dict[str, Any]:
        if cq_id is None:
            cq_id = f"cq{self._next_cq_id}"
            self._next_cq_id += 1
        update = {
            "callback_query": {
                "id": cq_id,
                "from": {"id": from_id, "is_bot": False, "first_name": "T"},
                "message": {"message_id": message_id, "chat": {"id": chat_id, "type": "private"}},
                "chat_instance": "1",
                "data": data,
            }
        }
        self.push_update(update)
        return update

    @property
    def last_sent(self) -> dict[str, Any]:
        return self.sent[-1]

    @staticmethod
    def button_data(message: dict[str, Any], kind: str) -> str:
        for row in message["reply_markup"]["inline_keyboard"]:
            for button in row:
                if button["callback_data"].endswith(":" + kind):
                    return button["callback_data"]
        raise KeyError(kind)

    def click(
        self,
        kind: str = "a",
        *,
        from_id: int,
        chat_id: int | None = None,
        message_id: int | None = None,
        message: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Button kind ("a"/"d") der letzten (oder gegebenen) Nachricht klicken."""
        message = message or self.last_sent
        return self.push_callback(
            self.button_data(message, kind),
            from_id=from_id,
            chat_id=message["chat"]["id"] if chat_id is None else chat_id,
            message_id=message["message_id"] if message_id is None else message_id,
        )

    def calls_of(self, method: str) -> list[dict[str, Any]]:
        return [p for m, p in self.calls if m == method]

    def outgoing_texts(self) -> list[str]:
        texts = [p.get("text", "") for m, p in self.calls if m in ("sendMessage", "editMessageText")]
        texts += [p.get("text", "") for p in self.calls_of("answerCallbackQuery")]
        return texts
