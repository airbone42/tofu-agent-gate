import os
import unittest
from pathlib import Path, PurePosixPath
from unittest import mock

from tofu_agent_gate import config as configlib
from tofu_agent_gate.deadman import Systemd


def cfg():
    c = configlib.from_dict({"repo": {"url": "x"}, "deadman": {"minutes": 20, "unit_prefix": "gate-rb"}})
    c.source = PurePosixPath("/etc/gate/gate.yaml")
    return c


class DeadmanTest(unittest.TestCase):
    def test_argv_carries_config_and_pythonpath(self):
        with mock.patch.dict(os.environ, {"PYTHONPATH": "/opt/gate/current"}):
            argv = Systemd(cfg()).argv("run-1")
        self.assertIn("--unit=gate-rb-run-1", argv)
        self.assertIn("--on-active=20min", argv)
        self.assertIn("--setenv=GATE_CONFIG=/etc/gate/gate.yaml", argv)
        self.assertIn("--setenv=PYTHONPATH=/opt/gate/current", argv)
        self.assertEqual(argv[-3:], ["tofu_agent_gate", "rollback", "run-1"])

    def test_pythonpath_falls_back_to_package_root(self):
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        with mock.patch.dict(os.environ, env, clear=True):
            argv = Systemd(cfg()).argv("run-1")
        pp = [a for a in argv if a.startswith("--setenv=PYTHONPATH=")][0].split("=", 2)[2]
        self.assertTrue((Path(pp) / "tofu_agent_gate" / "deadman.py").exists(), pp)


if __name__ == "__main__":
    unittest.main()
