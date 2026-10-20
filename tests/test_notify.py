"""notify mit Drossel: für systemd OnFailure= von Diensten, die jede Minute laufen."""

import tempfile
import unittest
from pathlib import Path

from tofu_agent_gate import config as configlib
from tofu_agent_gate.cli import notify_throttled


class FakeApprover:
    def __init__(self, ok=True):
        self.ok, self.sent = ok, []

    def notify(self, text):
        self.sent.append(text)
        return self.ok


class NotifyTest(unittest.TestCase):
    def setUp(self):
        tmp = Path(tempfile.mkdtemp())
        self.cfg = configlib.from_dict({"repo": {"url": "x"}, "state_dir": str(tmp / "state")})
        self.now = 1000.0

    def send(self, ap, **kw):
        return notify_throttled(self.cfg, ap, "Dienst **x** ausgefallen", clock=lambda: self.now, **kw)

    def test_throttle_per_key(self):
        ap = FakeApprover()
        self.assertEqual(self.send(ap, key="a.service", min_interval=3600), "sent")
        self.now += 60
        self.assertEqual(self.send(ap, key="a.service", min_interval=3600), "throttled")
        self.assertEqual(self.send(ap, key="b.service", min_interval=3600), "sent")
        self.now += 3600
        self.assertEqual(self.send(ap, key="a.service", min_interval=3600), "sent")
        self.assertEqual(len(ap.sent), 3)

    def test_without_key_always_sent(self):
        ap = FakeApprover()
        self.assertEqual([self.send(ap), self.send(ap)], ["sent", "sent"])

    def test_failed_send_does_not_start_throttle(self):
        self.assertEqual(self.send(FakeApprover(ok=False), key="a", min_interval=3600), "failed")
        self.assertEqual(self.send(FakeApprover(), key="a", min_interval=3600), "sent")

    def test_no_channel(self):
        self.assertEqual(self.send(None, key="a", min_interval=60), "failed")


if __name__ == "__main__":
    unittest.main()
