"""Tests für telegram.py und approve.py (Abnahme M3), ohne Netz."""

from __future__ import annotations

import io
import json
import logging
import os
import ssl
import tempfile
import time
import traceback
import unittest
import urllib.error
import urllib.parse
from pathlib import Path
from unittest import mock

try:
    from mock_telegram import FakeClock, MockTelegram
except ImportError:  # falls tests als Paket importiert wird
    from tests.mock_telegram import FakeClock, MockTelegram

from tofu_agent_gate import approve as approve_mod
from tofu_agent_gate.approve import (
    ACCEPTED,
    DECLINED,
    INVALID_HINT,
    MAX_REASON,
    REASON_LABEL,
    SEND_FAILED,
    TIMEOUT,
    Approver,
    tg_len,
)
from tofu_agent_gate.telegram import (
    TelegramApi,
    TelegramConfigError,
    TelegramError,
    from_env_file,
    load_env_file,
)

# Warnungen aus approve.py in Tests nicht ausgeben
logging.getLogger("tofu_agent_gate").addHandler(logging.NullHandler())

TOKEN = "123456789:AAHfakeTokenForTestsOnly_abcdefghijklmnop"
OWNER = 1001
CHAT = 2002
HASH_A = "a" * 8 + "0123456789abcdef" * 3 + "b" * 8
HASH_B = "c" * 64
FAKE_PEM = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
    "QyNTUxOQAAACBzZWNyZXRzZWNyZXRzZWNyZXRzZWNyZXRzZWNyZXQAAAAAAAAAAAAAAAA\n"
    "-----END OPENSSH PRIVATE KEY-----"
)


def full_trace(exc: BaseException) -> str:
    return "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))


class Base(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.store = Path(self._tmp.name) / "approvals"
        self.clock = FakeClock()
        self.tg = MockTelegram(clock=self.clock)
        self.api = TelegramApi(TOKEN, transport=self.tg)
        self.approver = self.make_approver()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def make_approver(self, **kwargs) -> Approver:
        kwargs.setdefault("clock", self.clock.time)
        kwargs.setdefault("sleep", self.clock.sleep)
        return Approver(self.api, OWNER, CHAT, self.store, **kwargs)

    def ask(self, plan_hash: str = HASH_A, timeout_s: float = 600, **kwargs):
        kwargs.setdefault("summary", "2 Änderungen: unifi_dns_record.a (update)")
        return self.approver.request(plan_hash=plan_hash, timeout_s=timeout_s, **kwargs)

    def assert_buttons_removed(self, edit: dict) -> None:
        self.assertEqual(edit["reply_markup"], {"inline_keyboard": []})

    def hints(self) -> list[str]:
        return [a.get("text") for a in self.tg.answered]


class AcceptDeclineTest(Base):
    def test_accept_by_owner(self) -> None:
        self.tg.script = [lambda m: m.click("a", from_id=OWNER)]
        res = self.ask()
        self.assertTrue(res.approved)
        self.assertEqual(res.reason, ACCEPTED)
        self.assertRegex(res.request_id, r"^[0-9a-f]{16}$")
        self.assertEqual(self.hints(), ["Angenommen"])
        self.assertEqual(len(self.tg.edited), 1)
        edit = self.tg.edited[0]
        self.assertEqual(edit["message_id"], self.tg.sent[0]["message_id"])
        self.assertIn("<b>Freigegeben</b>", edit["text"])
        self.assert_buttons_removed(edit)
        rec = self.approver.load_record(res.request_id)
        self.assertEqual(rec["status"], "approved")
        self.assertEqual(rec["plan_hash"], HASH_A)

    def test_decline_by_owner(self) -> None:
        self.tg.script = [lambda m: m.click("d", from_id=OWNER)]
        res = self.ask()
        self.assertFalse(res.approved)
        self.assertEqual(res.reason, DECLINED)
        self.assertEqual(self.hints(), ["Abgelehnt"])
        self.assertIn("<b>Abgelehnt</b>", self.tg.edited[0]["text"])
        self.assert_buttons_removed(self.tg.edited[0])
        self.assertEqual(self.approver.load_record(res.request_id)["status"], "declined")

    def test_message_format_and_buttons(self) -> None:
        self.tg.script = [lambda m: m.click("d", from_id=OWNER)]
        res = self.ask(agent_reason="DNS für neuen Host", link="https://git.example/c/1")
        sent = self.tg.sent[0]
        params = sent["params"]
        self.assertEqual(params["chat_id"], CHAT)
        text = params["text"]
        self.assertTrue(text.startswith("<b>Freigabe nötig</b>"))
        self.assertEqual(params["parse_mode"], "HTML")
        self.assertIn("Plan " + HASH_A[:8], text)
        self.assertNotIn(HASH_A, text)
        self.assertNotIn(res.request_id, text)
        self.assertIn("2 Änderungen", text)
        self.assertIn("<i>" + REASON_LABEL + "</i>\nDNS für neuen Host", text)
        self.assertIn('<a href="https://git.example/c/1">Commit</a>', text)
        buttons = params["reply_markup"]["inline_keyboard"][0]
        self.assertEqual([b["text"] for b in buttons], ["Accept", "Decline"])
        self.assertEqual(
            [b["callback_data"] for b in buttons], [f"{res.request_id}:a", f"{res.request_id}:d"]
        )

    def test_request_id_from_secrets(self) -> None:
        with mock.patch.object(approve_mod.secrets, "token_hex", return_value="00ff00ff00ff00ff") as th:
            self.tg.script = [lambda m: m.click("a", from_id=OWNER)]
            res = self.ask()
        th.assert_called_with(8)
        self.assertEqual(res.request_id, "00ff00ff00ff00ff")

    def test_agent_text_cannot_inject_markup(self) -> None:
        self.tg.script = [lambda m: m.click("a", from_id=OWNER)]
        self.ask(agent_reason='<b>fett</b> <a href="http://evil">x</a> **y**\nzweite Zeile')
        self.approver.notify('Lauf <a href="http://evil">fertig</a>')
        for method in ("sendMessage", "editMessageText"):
            calls = self.tg.calls_of(method)
            self.assertTrue(calls)
            for p in calls:
                self.assertEqual(p.get("parse_mode"), "HTML")
                self.assertNotIn("entities", p)
                self.assertNotIn('<a href="http://evil"', p["text"])
                self.assertNotIn("<b>fett", p["text"])
        sent = self.tg.calls_of("sendMessage")[0]["text"]
        self.assertIn("&lt;b&gt;fett&lt;/b&gt;", sent)
        self.assertIn("**y**", sent)  # Begründung: keine Fett-Umwandlung
        self.assertNotIn("zweite Zeile", sent)  # nur die erste Zeile


class ForeignClickTest(Base):
    def run_invalid(self, **click) -> None:
        self.tg.script = [lambda m: m.click("a", **click)]
        res = self.ask(timeout_s=300)
        self.assertFalse(res.approved)
        self.assertEqual(res.reason, TIMEOUT)
        self.assertEqual(self.hints(), [INVALID_HINT])
        # einzige Bearbeitung ist die Ablaufmeldung
        self.assertEqual(len(self.tg.edited), 1)
        self.assertIn("Abgelaufen", self.tg.edited[0]["text"])
        self.assertEqual(self.approver.load_record(res.request_id)["status"], "expired")

    def test_foreign_user_rejected(self) -> None:
        self.run_invalid(from_id=999)

    def test_foreign_chat_rejected(self) -> None:
        self.run_invalid(from_id=OWNER, chat_id=999)

    def test_foreign_message_id_rejected(self) -> None:
        self.run_invalid(from_id=OWNER, message_id=4711)

    def test_foreign_then_owner(self) -> None:
        self.tg.script = [
            lambda m: m.click("a", from_id=999),
            lambda m: m.click("a", from_id=OWNER),
        ]
        res = self.ask()
        self.assertTrue(res.approved)
        self.assertEqual(self.hints(), [INVALID_HINT, "Angenommen"])

    def test_garbage_callback_data(self) -> None:
        def act(m: MockTelegram) -> None:
            msg = m.last_sent
            for data in ("x", "", "ABCDEF0123456789:a", msg["reply_markup"]["inline_keyboard"][0][0]["callback_data"] + "x"):
                m.push_callback(data, from_id=OWNER, chat_id=CHAT, message_id=msg["message_id"])

        self.tg.script = [act]
        res = self.ask(timeout_s=120)
        self.assertFalse(res.approved)
        self.assertEqual(self.hints(), [INVALID_HINT] * 4)


class ExpiryTest(Base):
    def test_timeout_is_decline_and_edits_message(self) -> None:
        start = self.clock.now
        real_start = time.monotonic()
        res = self.ask(timeout_s=1800)
        self.assertFalse(res.approved)
        self.assertEqual(res.reason, TIMEOUT)
        self.assertGreaterEqual(self.clock.now - start, 1800)
        self.assertLess(time.monotonic() - real_start, 5)
        self.assertEqual(len(self.tg.edited), 1)
        edit = self.tg.edited[0]
        self.assertIn("Abgelaufen", edit["text"])
        self.assert_buttons_removed(edit)
        self.assertEqual(self.approver.load_record(res.request_id)["status"], "expired")
        # Long Polling mit allowed_updates und Poll-Timeout höchstens 50
        polls = self.tg.calls_of("getUpdates")
        self.assertTrue(polls)
        for p in polls:
            self.assertEqual(p["allowed_updates"], ["callback_query"])
            self.assertLessEqual(p["timeout"], 50)

    def test_click_after_expiry_rejected(self) -> None:
        def late(m: MockTelegram) -> None:
            self.clock.advance(400)
            m.click("a", from_id=OWNER)

        self.tg.script = [late]
        res = self.ask(timeout_s=300)
        self.assertFalse(res.approved)
        self.assertEqual(res.reason, TIMEOUT)
        self.assertEqual(self.hints(), [INVALID_HINT])


class ReplayTest(Base):
    def test_double_click_counts_once(self) -> None:
        def twice(m: MockTelegram) -> None:
            m.click("a", from_id=OWNER)
            m.click("d", from_id=OWNER)

        self.tg.script = [twice]
        res = self.ask()
        self.assertTrue(res.approved)
        self.assertEqual(self.hints(), ["Angenommen", INVALID_HINT])

    def test_replay_after_restart_rejected(self) -> None:
        captured: dict = {}

        def accept(m: MockTelegram) -> None:
            captured.update(m.click("a", from_id=OWNER)["callback_query"])

        self.tg.script = [accept]
        first = self.ask()
        self.assertTrue(first.approved)
        last_update = 5000  # erstes Update-ID des Mocks
        offset_file = json.loads((self.store / "offset.json").read_text(encoding="utf-8"))
        self.assertEqual(offset_file["offset"], last_update + 1)

        # neuer Prozess: neues Approver-Objekt, gleicher store_dir
        self.approver = self.make_approver()

        def replay(m: MockTelegram) -> None:
            m.push_callback(
                captured["data"], from_id=OWNER, chat_id=CHAT,
                message_id=captured["message"]["message_id"],
            )

        self.tg.answered.clear()
        polls_before = len(self.tg.calls_of("getUpdates"))
        self.tg.script = [replay]
        second = self.ask(plan_hash=HASH_A, timeout_s=120)
        self.assertFalse(second.approved)
        self.assertEqual(second.reason, TIMEOUT)
        self.assertNotEqual(first.request_id, second.request_id)
        self.assertEqual(self.hints(), [INVALID_HINT])
        # Offset wurde aus dem Store übernommen
        self.assertEqual(self.tg.calls_of("getUpdates")[polls_before]["offset"], last_update + 1)
        self.assertEqual(self.approver.load_record(first.request_id)["status"], "approved")

    def test_redelivered_update_without_offset_rejected(self) -> None:
        """Auch wenn der Offset verloren geht, zählt ein Klick nicht zweimal."""
        self.tg.script = [lambda m: m.click("a", from_id=OWNER)]
        first = self.ask()
        self.assertTrue(first.approved)
        record = self.approver.load_record(first.request_id)
        (self.store / "offset.json").unlink()
        approver2 = self.make_approver()
        # simuliert: alte Anfrage käme nochmals dran, Prüfung liest den Store
        cq = {
            "id": "x", "data": f"{first.request_id}:a", "from": {"id": OWNER},
            "message": {"message_id": record["message_id"], "chat": {"id": CHAT}},
        }
        self.assertIsNone(approver2._check_click(cq, first.request_id, HASH_A))


class PlanHashTest(Base):
    def test_click_of_other_request_rejected(self) -> None:
        # Anfrage mit Hash B läuft ab, ihre Nachricht bleibt
        old = self.ask(plan_hash=HASH_B, timeout_s=60)
        self.assertFalse(old.approved)
        old_msg = self.tg.sent[0]
        self.tg.answered.clear()

        # Anfrage mit Hash A offen, Klick kommt von der Nachricht zu Hash B
        def click_old(m: MockTelegram) -> None:
            m.click("a", from_id=OWNER, message=old_msg)

        def mixed(m: MockTelegram) -> None:
            # Request-ID von A, message_id von B
            m.push_callback(
                m.button_data(m.last_sent, "a"), from_id=OWNER, chat_id=CHAT,
                message_id=old_msg["message_id"],
            )

        self.tg.script = [click_old, mixed]
        res = self.ask(plan_hash=HASH_A, timeout_s=300)
        self.assertFalse(res.approved)
        self.assertEqual(self.hints(), [INVALID_HINT, INVALID_HINT])

    def test_stored_plan_hash_must_match(self) -> None:
        def tamper_then_click(m: MockTelegram) -> None:
            rid = m.button_data(m.last_sent, "a").split(":")[0]
            path = self.store / "requests" / f"{rid}.json"
            rec = json.loads(path.read_text(encoding="utf-8"))
            rec["plan_hash"] = HASH_B
            path.write_text(json.dumps(rec), encoding="utf-8")
            m.click("a", from_id=OWNER)

        self.tg.script = [tamper_then_click]
        res = self.ask(plan_hash=HASH_A, timeout_s=300)
        self.assertFalse(res.approved)
        self.assertEqual(self.hints(), [INVALID_HINT])


class TextTest(Base):
    def test_truncated_to_4096_with_link(self) -> None:
        link = "https://git.example/infra/config/commit/abc123"
        self.tg.script = [lambda m: m.click("a", from_id=OWNER)]
        self.ask(summary="x" * 10_000, agent_reason="r" * 5000, link=link)
        text = self.tg.sent[0]["params"]["text"]
        self.assertLessEqual(tg_len(text), 4096)
        self.assertIn(f'<a href="{link}">Commit</a>', text)
        reason = text.split(REASON_LABEL + "</i>\n", 1)[1].split("\n\n", 1)[0]
        self.assertLessEqual(len(reason), MAX_REASON)
        self.assertTrue(reason.startswith("rrrr"))
        for edit in self.tg.edited:
            self.assertLessEqual(tg_len(edit["text"]), 4096)
            self.assertIn(f'<a href="{link}">Commit</a>', edit["text"])

    def test_truncation_counts_utf16(self) -> None:
        self.tg.script = [lambda m: m.click("a", from_id=OWNER)]
        res = self.ask(summary="\U0001F600" * 5000)
        self.assertTrue(res.approved)  # Mock hätte zu lange Texte abgelehnt
        self.assertLessEqual(tg_len(self.tg.sent[0]["params"]["text"]), 4096)

    def test_notify_truncated(self) -> None:
        self.assertTrue(self.approver.notify("y" * 9000))
        self.assertLessEqual(tg_len(self.tg.sent[0]["params"]["text"]), 4096)
        self.assertEqual(self.tg.sent[0]["params"]["chat_id"], CHAT)


class RedactionTest(Base):
    def test_pem_key_not_sent(self) -> None:
        self.tg.script = [lambda m: m.click("a", from_id=OWNER)]
        # Key in der ersten Zeile der Begründung: wird vor dem Kürzen auf eine Zeile redigiert
        self.ask(summary="Key: " + FAKE_PEM, agent_reason=FAKE_PEM + "\nEnde")
        self.approver.notify("Fertig, Token " + TOKEN + " und " + FAKE_PEM)
        texts = self.tg.outgoing_texts()
        self.assertTrue(texts)
        for text in texts:
            self.assertNotIn("PRIVATE KEY", text)
            self.assertNotIn("b3BlbnNzaC1rZXktdjEA", text)
            self.assertNotIn(TOKEN, text)
        sent = self.tg.sent[0]["params"]["text"]
        self.assertIn("&lt;redacted&gt;", sent.split("ungeprüft):</i>", 1)[1])
        self.assertIn("Key: &lt;redacted&gt;", sent)

    def test_long_reason_with_key_cut_after_redaction(self) -> None:
        reason = "a" * 790 + FAKE_PEM
        self.tg.script = [lambda m: m.click("d", from_id=OWNER)]
        self.ask(agent_reason=reason)
        for text in self.tg.outgoing_texts():
            self.assertNotIn("b3BlbnNzaC1rZXktdjEA", text)
            self.assertNotIn("BEGIN OPENSSH", text)

    def test_custom_redactor_applies_to_everything(self) -> None:
        seen: list[str] = []

        def red(text: str) -> str:
            seen.append(text)
            return text.replace("GEHEIM", "<x>").replace("Angenommen", "Angenommen.").replace(
                INVALID_HINT, INVALID_HINT + "."
            )

        self.approver = self.make_approver(redact=red)
        self.tg.script = [
            lambda m: m.click("a", from_id=999),
            lambda m: m.click("a", from_id=OWNER),
        ]
        self.approver.request(plan_hash=HASH_A, summary="GEHEIM", agent_reason="GEHEIM",
                              link="https://x/GEHEIM", timeout_s=300)
        self.approver.notify("GEHEIM")
        for text in self.tg.outgoing_texts():
            self.assertNotIn("GEHEIM", text)
        self.assertEqual(self.hints(), [INVALID_HINT + ".", "Angenommen."])
        self.assertTrue(seen)


class NetworkTest(Base):
    def test_poll_errors_backoff_then_accept(self) -> None:
        self.tg.fail(
            "getUpdates",
            OSError("Network is unreachable"),
            urllib.error.URLError("timed out"),
            {"ok": False, "error_code": 502, "description": "Bad Gateway"},
            {"ok": False, "error_code": 429, "description": "Too Many Requests",
             "parameters": {"retry_after": 7}},
            ValueError("kaputtes JSON"),
        )
        self.tg.script = [lambda m: m.click("a", from_id=OWNER)]
        res = self.ask()
        self.assertTrue(res.approved)
        self.assertEqual(self.clock.sleeps, [1.0, 2.0, 4.0, 7.0, 16.0])

    def test_permanent_poll_error_is_decline(self) -> None:
        self.tg.break_method("getUpdates", lambda: OSError("Connection refused"))
        real_start = time.monotonic()
        res = self.ask(timeout_s=1800)
        self.assertFalse(res.approved)
        self.assertEqual(res.reason, TIMEOUT)
        self.assertLess(time.monotonic() - real_start, 5)
        self.assertTrue(self.clock.sleeps)
        self.assertLessEqual(max(self.clock.sleeps), 60)
        self.assertEqual(len(self.tg.edited), 1)
        rec = self.approver.load_record(res.request_id)
        self.assertEqual(rec["status"], "expired")
        self.assertIn("Connection refused", rec["last_error"])

    def test_send_failure_is_decline(self) -> None:
        self.tg.break_method("sendMessage", lambda: OSError("down"))
        res = self.ask()
        self.assertFalse(res.approved)
        self.assertEqual(res.reason, SEND_FAILED)
        self.assertEqual(len(self.tg.calls_of("sendMessage")), 3)
        self.assertEqual(self.tg.calls_of("getUpdates"), [])

    def test_edit_and_answer_errors_do_not_crash(self) -> None:
        self.tg.break_method("editMessageText", lambda: OSError("down"))
        self.tg.break_method("answerCallbackQuery", lambda: OSError("down"))
        self.tg.script = [lambda m: m.click("a", from_id=OWNER)]
        self.assertTrue(self.ask().approved)

    def test_notify_error_returns_false(self) -> None:
        self.tg.break_method("sendMessage", lambda: OSError("down"))
        self.assertFalse(self.approver.notify("x"))

    def test_other_updates_ignored_offset_counts(self) -> None:
        def act(m: MockTelegram) -> None:
            m.push_update({"message": {"message_id": 1, "chat": {"id": CHAT}, "text": "hallo"}})
            m.push_update({"edited_message": {"message_id": 1}})

        def accept(m: MockTelegram) -> None:
            m.click("a", from_id=OWNER)

        self.tg.script = [act, accept]
        res = self.ask()
        self.assertTrue(res.approved)
        polls = self.tg.calls_of("getUpdates")
        self.assertEqual(polls[1]["offset"], 5002)
        self.assertEqual(self.tg.answered[0]["text"], "Angenommen")
        self.assertEqual(len(self.tg.answered), 1)


class StoreTest(Base):
    def test_files_atomic_and_private(self) -> None:
        self.tg.script = [lambda m: m.click("a", from_id=OWNER)]
        res = self.ask()
        files = sorted(p.name for p in (self.store / "requests").iterdir())
        self.assertEqual(files, [f"{res.request_id}.json"])
        self.assertFalse(list(self.store.glob("*.tmp")) + list(self.store.glob(".*.tmp")))
        if os.name == "posix":
            for path in (self.store / "requests" / files[0], self.store / "offset.json"):
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_corrupt_record_is_invalid(self) -> None:
        def corrupt_then_click(m: MockTelegram) -> None:
            rid = m.button_data(m.last_sent, "a").split(":")[0]
            (self.store / "requests" / f"{rid}.json").write_text("{kaputt", encoding="utf-8")
            m.click("a", from_id=OWNER)

        self.tg.script = [corrupt_then_click]
        res = self.ask(timeout_s=120)
        self.assertFalse(res.approved)
        self.assertEqual(self.hints(), [INVALID_HINT])


class TelegramApiTest(unittest.TestCase):
    def test_call_returns_result_and_raises_on_not_ok(self) -> None:
        api = TelegramApi(TOKEN, transport=lambda m, p: {"ok": True, "result": {"m": m, "p": p}})
        self.assertEqual(api.call("getMe", a=1, b=None), {"m": "getMe", "p": {"a": 1}})
        api = TelegramApi(TOKEN, transport=lambda m, p: {
            "ok": False, "error_code": 400, "description": "Bad Request: chat not found"})
        with self.assertRaises(TelegramError) as ctx:
            api.call("sendMessage", chat_id=1, text="x")
        self.assertIn("chat not found", str(ctx.exception))
        self.assertEqual(ctx.exception.error_code, 400)

    def test_token_never_in_exceptions(self) -> None:
        url = f"https://api.telegram.org/bot{TOKEN}/getUpdates"

        def boom(method, params):
            raise urllib.error.URLError(f"failed to reach {url}")

        def bad_desc(method, params):
            return {"ok": False, "error_code": 401, "description": f"Unauthorized {TOKEN}"}

        def quoted(method, params):
            raise OSError("x " + urllib.parse.quote(TOKEN, safe=""))

        for transport in (boom, bad_desc, quoted):
            api = TelegramApi(TOKEN, transport=transport)
            with self.assertRaises(TelegramError) as ctx:
                api.call("getUpdates", timeout=1)
            exc = ctx.exception
            for text in (str(exc), repr(exc), full_trace(exc), str(exc.description)):
                self.assertNotIn(TOKEN, text)
                self.assertNotIn(TOKEN.split(":")[1], text)
            self.assertIsNone(exc.__cause__)
            self.assertIsNone(exc.__context__)

        api = TelegramApi(TOKEN)
        self.assertNotIn(TOKEN, repr(api))
        self.assertNotIn(TOKEN, str(api))

    def test_default_transport_posts_json_with_tls(self) -> None:
        seen = {}

        class Resp(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def fake_urlopen(req, timeout, context):
            seen.update(url=req.full_url, data=json.loads(req.data), method=req.get_method(),
                        ctype=req.get_header("Content-type"), timeout=timeout, ctx=context)
            return Resp(b'{"ok": true, "result": [1]}')

        api = TelegramApi(TOKEN, timeout=60)
        with mock.patch("urllib.request.urlopen", fake_urlopen):
            self.assertEqual(api.call("getUpdates", timeout=50, offset=3), [1])
        self.assertEqual(seen["url"], f"https://api.telegram.org/bot{TOKEN}/getUpdates")
        self.assertEqual(seen["method"], "POST")
        self.assertEqual(seen["ctype"], "application/json")
        self.assertEqual(seen["data"], {"timeout": 50, "offset": 3})
        self.assertGreater(seen["timeout"], 50)
        self.assertEqual(seen["ctx"].verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(seen["ctx"].check_hostname)

    def test_default_transport_errors_without_token(self) -> None:
        url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"

        def http_error(req, timeout, context):
            raise urllib.error.HTTPError(
                url, 403, "Forbidden", {}, io.BytesIO(b'{"ok": false, "error_code": 403, '
                                                       b'"description": "Forbidden: bot was blocked"}'))

        def http_garbage(req, timeout, context):
            raise urllib.error.HTTPError(url, 502, "Bad Gateway", {}, io.BytesIO(b"<html>"))

        def url_error(req, timeout, context):
            raise urllib.error.URLError(f"cannot connect {req.full_url}")

        api = TelegramApi(TOKEN)
        for fn, expect in ((http_error, "bot was blocked"), (http_garbage, "HTTP 502"),
                           (url_error, "cannot connect")):
            with mock.patch("urllib.request.urlopen", fn):
                with self.assertRaises(TelegramError) as ctx:
                    api.call("sendMessage", chat_id=1, text="x")
            self.assertIn(expect, str(ctx.exception))
            self.assertNotIn(TOKEN, full_trace(ctx.exception))

    def test_invalid_method_name(self) -> None:
        api = TelegramApi(TOKEN, transport=lambda m, p: {"ok": True})
        with self.assertRaises(TelegramError):
            api.call("../getMe")

    def test_empty_token(self) -> None:
        with self.assertRaises(TelegramConfigError):
            TelegramApi("")


class EnvFileTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "telegram.env"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def write(self, text: str) -> Path:
        self.path.write_text(text, encoding="utf-8")
        return self.path

    def test_parse(self) -> None:
        env = load_env_file(self.write(
            "# Kommentar\n"
            "\n"
            "A=1\n"
            "export B = zwei # Kommentar\n"
            "C='mit # Raute'\n"
            'D="esc \\" quote"\n'
            "E=x#y\n"
            "F=\n"
        ))
        self.assertEqual(env, {"A": "1", "B": "zwei", "C": "mit # Raute",
                               "D": 'esc " quote', "E": "x#y", "F": ""})

    def test_from_env_file(self) -> None:
        cfg = from_env_file(self.write(
            f'TELEGRAM_BOT_TOKEN="{TOKEN}"\nTELEGRAM_OWNER_ID=1001\nTELEGRAM_CHAT_ID=-2002\n'))
        self.assertEqual((cfg.token, cfg.owner_id, cfg.chat_id), (TOKEN, 1001, -2002))
        self.assertNotIn(TOKEN, repr(cfg))
        self.assertNotIn(TOKEN, repr(cfg.api(transport=lambda m, p: {"ok": True})))

    def test_missing_values_without_token(self) -> None:
        path = self.write(f"TELEGRAM_BOT_TOKEN={TOKEN}\nTELEGRAM_OWNER_ID=1\n")
        with self.assertRaises(TelegramConfigError) as ctx:
            from_env_file(path)
        self.assertIn("TELEGRAM_CHAT_ID", str(ctx.exception))
        self.assertNotIn(TOKEN, full_trace(ctx.exception))

    def test_bad_values_without_token(self) -> None:
        cases = [
            f"TELEGRAM_BOT_TOKEN={TOKEN}\nTELEGRAM_OWNER_ID=abc\nTELEGRAM_CHAT_ID=1\n",
            f"TELEGRAM_BOT_TOKEN '{TOKEN}'\n",
            f"TELEGRAM_BOT_TOKEN='{TOKEN}\n",
            f"TELEGRAM_BOT_TOKEN='{TOKEN}' rest\n",
        ]
        for text in cases:
            with self.assertRaises(TelegramConfigError) as ctx:
                from_env_file(self.write(text))
            self.assertNotIn(TOKEN, full_trace(ctx.exception))


if __name__ == "__main__":
    unittest.main()
