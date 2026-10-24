"""Tests für delegate.py und die Stufe review im Approver, ohne Netz."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

try:
    from mock_telegram import FakeClock, MockTelegram
except ImportError:  # falls tests als Paket importiert wird
    from tests.mock_telegram import FakeClock, MockTelegram

from tofu_agent_gate.approve import ACCEPTED, DELEGATE_DENIED, DELEGATED, Approver
from tofu_agent_gate.delegate import ESCALATE, CommandDelegate, Verdict, parse
from tofu_agent_gate.telegram import TelegramApi

TOKEN = "123456789:AAHfakeTokenForTestsOnly_abcdefghijklmnop"
OWNER = 1001
CHAT = 2002
HASH = "c" * 64


class ParseTest(unittest.TestCase):
    def test_last_json_line_counts(self):
        out = 'Log\n{"decision": "deny", "by": "x"}\n{"decision": "approve", "by": "hermes", "note": "passt"}\n'
        self.assertEqual(parse(out), Verdict("approve", "hermes", "passt"))

    def test_garbage_escalates(self):
        for out in ("", "ok", '{"decision": "yes"}', "{kaputt", '["approve"]'):
            self.assertEqual(parse(out).decision, ESCALATE, out)

    def test_note_and_by_are_cut_and_cleaned(self):
        v = parse(json.dumps({"decision": "deny", "by": "h" * 99, "note": "a\x00b" + "x" * 900}))
        self.assertEqual(len(v.by), 40)
        self.assertEqual(len(v.note), 500)
        self.assertNotIn("\x00", v.note)


class CommandDelegateTest(unittest.TestCase):
    def script(self, body: str) -> list[str]:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        path = Path(self._tmp.name) / "d.py"
        path.write_text(body, encoding="utf-8")
        return [sys.executable, str(path)]

    def test_gets_request_on_stdin(self):
        cmd = self.script("import json, sys\nr = json.load(sys.stdin)\n"
                          "print(json.dumps({'decision': 'approve', 'by': 'h', 'note': r['summary']}))\n")
        v = CommandDelegate(cmd)({"summary": "DNS x", "timeout_s": 5})
        self.assertEqual(v, Verdict("approve", "h", "DNS x"))

    def test_exit_code_escalates(self):
        cmd = self.script("print('{\"decision\": \"approve\"}')\nraise SystemExit(3)\n")
        self.assertEqual(CommandDelegate(cmd)({"timeout_s": 5}).decision, ESCALATE)

    def test_timeout_and_missing_binary_escalate(self):
        def slow(*a, **kw):
            raise subprocess.TimeoutExpired(a[0], 1)

        self.assertEqual(CommandDelegate(["x"], run=slow)({"timeout_s": 1}).decision, ESCALATE)
        self.assertEqual(CommandDelegate(["/nicht/da"])({"timeout_s": 1}).decision, ESCALATE)


class ApproverDelegateTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.clock = FakeClock()
        self.tg = MockTelegram(clock=self.clock)
        self.asked = []

    def tearDown(self):
        self._tmp.cleanup()

    def approver(self, verdict: Verdict) -> Approver:
        def delegate(req):
            self.asked.append(req)
            return verdict

        return Approver(TelegramApi(TOKEN, transport=self.tg), OWNER, CHAT, Path(self._tmp.name) / "a",
                        clock=self.clock.time, sleep=self.clock.sleep, delegate=delegate)

    def test_approve_without_telegram(self):
        ap = self.approver(Verdict("approve", "hermes", "passt zum Auftrag"))
        res = ap.request(plan_hash=HASH, summary="Netz x", agent_reason="für y", timeout_s=60, delegate=True)
        self.assertEqual((res.approved, res.reason, res.note), (True, DELEGATED, "passt zum Auftrag"))
        self.assertEqual(self.tg.sent, [])
        rec = ap.load_record(res.request_id)
        self.assertEqual((rec["status"], rec["decided_by"]), ("approved", "delegate:hermes"))
        self.assertEqual(self.asked[0]["agent_reason"], "für y")
        self.assertEqual(self.asked[0]["plan_hash"], HASH)

    def test_deny_without_telegram(self):
        ap = self.approver(Verdict("deny", "hermes", "kein Auftrag"))
        res = ap.request(plan_hash=HASH, summary="Netz x", timeout_s=60, delegate=True)
        self.assertEqual((res.approved, res.reason), (False, DELEGATE_DENIED))
        self.assertEqual(self.tg.sent, [])
        self.assertEqual(ap.load_record(res.request_id)["status"], "declined")

    def test_escalate_asks_telegram_with_note(self):
        ap = self.approver(Verdict("escalate", "hermes", "ungewöhnlich spät"))
        self.tg.script = [lambda m: m.click("a", from_id=OWNER)]
        res = ap.request(plan_hash=HASH, summary="Netz x", timeout_s=60, delegate=True)
        self.assertEqual((res.approved, res.reason), (True, ACCEPTED))
        self.assertIn("hermes gibt das an dich weiter: ungewöhnlich spät", self.tg.sent[0]["params"]["text"])

    def test_without_flag_delegate_is_not_asked(self):
        ap = self.approver(Verdict("approve", "hermes"))
        self.tg.script = [lambda m: m.click("d", from_id=OWNER)]
        res = ap.request(plan_hash=HASH, summary="Netz x", timeout_s=60)
        self.assertFalse(res.approved)
        self.assertEqual(self.asked, [])
        self.assertEqual(len(self.tg.sent), 1)

    def owner_approver(self, verdict: Verdict) -> Approver:
        ap = self.approver(verdict)
        ap.delegate_owner = "tobias"
        return ap

    def test_owner_routing_sends_approval_level_to_delegate(self):
        ap = self.owner_approver(Verdict("approve", "tobias", "per Klick"))
        res = ap.request(plan_hash=HASH, summary="Policy löschen", timeout_s=60,
                         context={"source": "enroll", "requested_by": "coach", "plan_hash": "x"})
        self.assertEqual((res.approved, res.reason), (True, DELEGATED))
        self.assertEqual(self.tg.sent, [])
        req = self.asked[0]
        self.assertTrue(req["must_ask"])
        self.assertEqual((req["source"], req["requested_by"], req["plan_hash"]), ("enroll", "coach", HASH))

    def test_owner_routing_needs_owner_click(self):
        ap = self.owner_approver(Verdict("approve", "hermes", "sieht gut aus"))
        self.tg.script = [lambda m: m.click("d", from_id=OWNER)]
        res = ap.request(plan_hash=HASH, summary="Policy löschen", timeout_s=60)
        self.assertFalse(res.approved)
        self.assertIn("hermes gibt das an dich weiter: sieht gut aus", self.tg.sent[0]["params"]["text"])

    def test_owner_routing_delegate_may_deny(self):
        ap = self.owner_approver(Verdict("deny", "hermes", "nein"))
        res = ap.request(plan_hash=HASH, summary="Policy löschen", timeout_s=60)
        self.assertEqual((res.approved, res.reason), (False, DELEGATE_DENIED))

    def test_review_level_is_not_must_ask_and_direct_skips_delegate(self):
        ap = self.owner_approver(Verdict("approve", "hermes"))
        self.assertTrue(ap.request(plan_hash=HASH, summary="x", timeout_s=60, delegate=True).approved)
        self.assertFalse(self.asked[0]["must_ask"])
        self.tg.script = [lambda m: m.click("a", from_id=OWNER)]
        ap.request(plan_hash=HASH, summary="x", timeout_s=60, direct=True)
        self.assertEqual(len(self.asked), 1)
        self.assertEqual(len(self.tg.sent), 1)

    def test_secrets_are_redacted_before_delegate(self):
        ap = self.approver(Verdict("approve", "hermes"))
        ap.request(plan_hash=HASH, summary=f"Token {TOKEN}", timeout_s=60, delegate=True)
        self.assertNotIn(TOKEN, json.dumps(self.asked[0]))


if __name__ == "__main__":
    unittest.main()
