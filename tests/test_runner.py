"""Ende-zu-Ende-Tests des Runners: echtes Git, gefälschtes tofu, Hooks als Skripte."""

import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from dataclasses import dataclass
from pathlib import Path

from tofu_agent_gate import config as configlib
from tofu_agent_gate.gitops import Git
from tofu_agent_gate.hooks import Hooks
from tofu_agent_gate.policy import Policy
from tofu_agent_gate.runner import Deps, Run, Runner

from fake_tofu import Crash, FakeTofu

POLICY = {
    "version": 1,
    "limits": {"max_changes": 5, "allow_delete": ["unifi_dns_record"]},
    "forbidden": [{"type": "unifi_setting"}, {"references": ["forbidden.example"]}],
    "rules": [{"level": "auto", "type": "unifi_dns_record", "where": {"name": {"regex": r".*\.auto\.example"}}}],
    "default": "approval",
}

SEED = {"dns_records": {"host-1": {"name": "host-1.auto.example", "record_type": "A", "value": "198.51.100.1"}}}


def git(*args, cwd):
    env = dict(os.environ, GIT_AUTHOR_NAME="agent", GIT_AUTHOR_EMAIL="agent@localhost",
               GIT_COMMITTER_NAME="agent", GIT_COMMITTER_EMAIL="agent@localhost")
    r = subprocess.run(["git", *args], cwd=cwd, env=env, capture_output=True, text=True)
    if r.returncode:
        raise AssertionError(f"git {args}: {r.stderr}")
    return r.stdout.strip()


@dataclass
class Res:
    approved: bool
    reason: str
    request_id: str = "r"


class FakeApprover:
    def __init__(self, answer=True):
        self.answer = answer
        self.requests = []
        self.notes = []

    def request(self, **kw):
        self.requests.append(kw)
        return Res(self.answer, "accepted" if self.answer else "declined")

    def notify(self, text):
        self.notes.append(text)


class FakeDeadman:
    def __init__(self):
        self.scheduled, self.cancelled = [], []

    def schedule(self, run_id):
        self.scheduled.append(run_id)

    def cancel(self, run_id):
        self.cancelled.append(run_id)


class RunnerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="gate-test-"))
        self.origin = self.tmp / "origin.git"
        git("init", "--bare", "-q", "-b", "main", str(self.origin), cwd=self.tmp)
        self.agent = self.tmp / "agent"
        git("clone", "-q", str(self.origin), str(self.agent), cwd=self.tmp)
        (self.agent / "tofu").mkdir(parents=True)
        (self.agent / "tofu" / "main.tf").write_text("# HCL aus main\n")
        self._write_data(SEED)
        git("add", "-A", cwd=self.agent)
        git("commit", "-q", "-m", "seed", cwd=self.agent)
        git("push", "-q", "origin", "HEAD:main", cwd=self.agent)

        self.controller = self.tmp / "controller.json"
        self.controller.write_text(json.dumps(
            {'unifi_dns_record.this["host-1"]': SEED["dns_records"]["host-1"]}))

        self.cfg = configlib.from_dict({
            "state_dir": str(self.tmp / "state"),
            "stop_file": str(self.tmp / "STOP"),
            "lock_file": str(self.tmp / "gate.lock"),
            "repo": {"url": str(self.origin), "workdir": str(self.tmp / "state" / "repo"),
                     "allowed_variables": ["dns_records"]},
            "tofu": {"state_path": str(self.tmp / "state" / "tofu" / "terraform.tfstate")},
            "policy": "unused",
            "hooks": {},
        })
        self.approver = FakeApprover()
        self.deadman = FakeDeadman()
        self.runner = self._runner()

    def _runner(self, hooks=None):
        if hooks is not None:
            self.cfg.hooks = hooks
        deps = Deps(
            git=Git(self.cfg),
            tofu_factory=lambda wd: FakeTofu(wd, self.controller),
            hooks=Hooks(self.cfg),
            policy=Policy.from_dict(POLICY),
            deadman=self.deadman,
            approver=self.approver,
        )
        return Runner(self.cfg, deps)

    def _write_data(self, data):
        (self.agent / "tofu" / "dns.auto.tfvars.json").write_text(json.dumps(data, indent=2))

    def _push_branch(self, name, data=None, extra_file=None, message="Agent: Änderung"):
        git("fetch", "-q", "origin", cwd=self.agent)
        git("checkout", "-q", "-B", name, "origin/main", cwd=self.agent)
        if data is not None:
            self._write_data(data)
        if extra_file:
            (self.agent / extra_file).parent.mkdir(parents=True, exist_ok=True)
            (self.agent / extra_file).write_text("x")
        git("add", "-A", cwd=self.agent)
        git("commit", "-q", "-m", message, cwd=self.agent)
        git("push", "-q", "-f", "origin", f"HEAD:refs/heads/{name}", cwd=self.agent)

    def _ctl(self):
        return json.loads(self.controller.read_text())

    def _branches(self):
        return git("branch", "--list", "--format=%(refname:short)", cwd=self.origin).splitlines()

    def _main_data(self):
        return json.loads(git("show", "main:tofu/dns.auto.tfvars.json", cwd=self.origin))

    def _with(self, key, rec):
        return {"dns_records": dict(SEED["dns_records"], **{key: rec})}

    def _hook_script(self, name, body):
        path = self.tmp / f"{name}.py"
        path.write_text(textwrap.dedent(body))
        return [sys.executable, str(path)]

    # ---------------------------------------------------------------- Fälle

    def test_auto_change_applied_and_merged(self):
        rec = {"name": "host-2.auto.example", "record_type": "A", "value": "198.51.100.2"}
        self._push_branch("desired/add-host-2", self._with("host-2", rec))
        [run] = self.runner.run_once()
        self.assertEqual(run.status, "applied", run.reasons)
        self.assertEqual(run.level, "auto")
        self.assertEqual(self._ctl()['unifi_dns_record.this["host-2"]'], rec)
        self.assertIn("host-2", self._main_data()["dns_records"])
        self.assertNotIn("desired/add-host-2", self._branches())
        self.assertEqual(self.deadman.scheduled, [run.run_id])
        self.assertIn(run.run_id, self.deadman.cancelled)
        self.assertEqual(self.approver.requests, [])

    def test_same_head_not_processed_twice(self):
        rec = {"name": "host-2.forbidden-not.example", "record_type": "A", "value": "198.51.100.2"}
        self.approver.answer = False
        self._push_branch("desired/x", self._with("host-2", rec))
        self.assertEqual(len(self.runner.run_once()), 1)
        self.assertEqual(self.runner.run_once(), [])

    def test_approval_requested_and_declined(self):
        rec = {"name": "other.example", "record_type": "A", "value": "198.51.100.3"}
        self.approver.answer = False
        self._push_branch("desired/other", self._with("other", rec), message="Brauche other.example")
        [run] = self.runner.run_once()
        self.assertEqual(run.status, "declined")
        self.assertEqual(len(self.approver.requests), 1)
        req = self.approver.requests[0]
        self.assertEqual(req["plan_hash"], run.plan_hash)
        self.assertIn("Brauche other.example", req["agent_reason"])
        self.assertNotIn('unifi_dns_record.this["other"]', self._ctl())
        self.assertIn("desired/other", self._branches())

    def test_approval_accepted_applies(self):
        rec = {"name": "other.example", "record_type": "A", "value": "198.51.100.3"}
        self._push_branch("desired/other", self._with("other", rec))
        [run] = self.runner.run_once()
        self.assertEqual(run.status, "applied", run.reasons)
        self.assertEqual(run.level, "approval")

    def test_forbidden_rejected_without_apply(self):
        rec = {"name": "x.auto.example", "record_type": "CNAME", "value": "forbidden.example"}
        self._push_branch("desired/bad", self._with("bad", rec))
        [run] = self.runner.run_once()
        self.assertEqual(run.status, "rejected")
        self.assertNotIn("apply", [c[0] for c in FakeTofu.calls if self.tmp.as_posix() in Path(c[1]).as_posix()])
        self.assertEqual(self.deadman.scheduled, [])
        self.assertTrue(any("Abgelehnt" in n for n in self.approver.notes))

    def test_hcl_change_rejected_before_plan(self):
        FakeTofu.calls.clear()
        self._push_branch("desired/hcl", extra_file="tofu/evil.tf")
        [run] = self.runner.run_once()
        self.assertEqual(run.status, "rejected")
        self.assertIn("tofu/evil.tf", " ".join(run.reasons))
        self.assertEqual(FakeTofu.calls, [])

    def test_unknown_variable_in_data_rejected(self):
        FakeTofu.calls.clear()
        self._push_branch("desired/pw", dict(SEED, state_passphrase="agent-chosen-passphrase"))
        [run] = self.runner.run_once()
        self.assertEqual(run.status, "rejected")
        self.assertIn("state_passphrase", " ".join(run.reasons))
        self.assertEqual(FakeTofu.calls, [])

    def test_invalid_branch_name_rejected(self):
        self._push_branch("desired/Bad Name".replace(" ", "_"), self._with("h", {"name": "h.auto.example"}))
        [run] = self.runner.run_once()
        self.assertEqual(run.status, "rejected")

    def test_stop_file_blocks_everything(self):
        self.cfg.stop_file.write_text("stop")
        self._push_branch("desired/a", self._with("a", {"name": "a.auto.example", "value": "1"}))
        self.assertEqual(self.runner.run_once(), [])

    def test_apply_failure_triggers_rollback(self):
        rec = {"name": "fail.auto.example", "record_type": "A", "value": "FAIL_APPLY"}
        self._push_branch("desired/fail", self._with("fail", rec))
        [run] = self.runner.run_once()
        self.assertEqual(run.status, "rolled_back", run.reasons)
        self.assertNotIn('unifi_dns_record.this["fail"]', self._ctl())
        self.assertEqual(self._main_data(), SEED)
        self.assertIn("desired/fail", self._branches())
        self.assertFalse(self.cfg.stop_file.exists())

    def test_silent_provider_error_detected_and_rolled_back(self):
        rec = {"name": "drift.auto.example", "record_type": "A", "value": "SILENT_DRIFT"}
        self._push_branch("desired/drift", self._with("drift", rec))
        [run] = self.runner.run_once()
        self.assertEqual(run.status, "rolled_back")
        self.assertTrue(any("nicht leer" in r for r in run.reasons))
        self.assertNotIn('unifi_dns_record.this["drift"]', self._ctl())

    def test_failing_post_apply_hook_triggers_rollback(self):
        hook = self._hook_script("post", """
            import json, os, sys
            print(json.dumps({"ok": False, "violations": [{"id": "inv-1", "message": "kaputt"}]}))
            sys.exit(1)
        """)
        runner = self._runner(hooks={"post_apply": hook})
        rec = {"name": "h.auto.example", "record_type": "A", "value": "198.51.100.9"}
        self._push_branch("desired/h", self._with("h", rec))
        [run] = runner.run_once()
        self.assertEqual(run.status, "rolled_back")
        self.assertTrue(any("inv-1" in r for r in run.reasons))
        self.assertEqual(self._ctl(), {'unifi_dns_record.this["host-1"]': SEED["dns_records"]["host-1"]})

    def test_pre_apply_hook_gets_plan_and_can_reject(self):
        hook = self._hook_script("pre", """
            import json, os, sys
            plan = json.load(open(os.environ["GATE_PLAN_JSON"]))
            names = [c["change"]["after"]["name"] for c in plan["resource_changes"] if c["change"]["after"]]
            bad = [n for n in names if n.startswith("bad")]
            print(json.dumps({"ok": not bad, "violations": [{"id": "no-bad", "message": n} for n in bad]}))
            sys.exit(1 if bad else 0)
        """)
        runner = self._runner(hooks={"pre_apply": hook})
        self._push_branch("desired/b", self._with("b", {"name": "bad.auto.example", "value": "1"}))
        [run] = runner.run_once()
        self.assertEqual(run.status, "rejected")
        self.assertTrue(any("no-bad" in r for r in run.reasons))
        self.assertEqual(self.deadman.scheduled, [])

    def _rollback_hooks(self, post_apply_fails=False):
        """Snapshot = Kopie des Controllers, post_rollback vergleicht vorher und nachher."""
        ctl = str(self.controller)
        log = self.tmp / "post_rollback.log"
        hooks = {
            "snapshot": self._hook_script("snap", f"""
                import os, shutil
                shutil.copy({ctl!r}, os.path.join(os.environ["GATE_SNAPSHOT_OUT"], "controller.json"))
            """),
            "post_rollback": self._hook_script("post_rb", f"""
                import json, os, sys
                env = {{k: v for k, v in os.environ.items() if k.startswith("GATE_")}}
                env["plan"] = json.load(open(env["GATE_PLAN_JSON"]))
                open({str(log)!r}, "w").write(json.dumps(env))
                load = lambda d: json.load(open(os.path.join(os.environ[d], "controller.json")))
                before, after = load("GATE_SNAPSHOT_BEFORE"), load("GATE_SNAPSHOT_AFTER")
                diff = sorted(a for a in set(before) | set(after) if before.get(a) != after.get(a))
                print(json.dumps({{"ok": not diff, "violations": [
                    {{"id": "unexpected-change", "message": a}} for a in diff]}}))
                sys.exit(1 if diff else 0)
            """),
        }
        if post_apply_fails:
            hooks["post_apply"] = self._hook_script("post", """
                import json, sys
                print(json.dumps({"ok": False, "violations": [{"id": "inv-1", "message": "kaputt"}]}))
                sys.exit(1)
            """)
        return hooks, log

    def _sticky_field_branch(self):
        """main setzt comment auf null, der Branch setzt ihn. Der Rollback lässt ihn stehen."""
        host = SEED["dns_records"]["host-1"]
        self._push_branch("main", {"dns_records": {"host-1": dict(host, comment=None)}})
        self._push_branch("desired/sticky", {"dns_records": {"host-1": dict(host, comment="vom Agenten")}})

    def test_rollback_check_passes_with_empty_plan(self):
        hooks, log = self._rollback_hooks()
        runner = self._runner(hooks=hooks)
        rec = {"name": "fail.auto.example", "record_type": "A", "value": "FAIL_APPLY"}
        self._push_branch("desired/fail", self._with("fail", rec))
        [run] = runner.run_once()
        self.assertEqual(run.status, "rolled_back", run.reasons)
        self.assertFalse(self.cfg.stop_file.exists())
        env = json.loads(log.read_text())
        self.assertEqual(env["GATE_PHASE"], "post_rollback")
        self.assertEqual(env["plan"]["resource_changes"], [])
        rdir = self.cfg.state_dir / "work" / run.run_id
        self.assertEqual(Path(env["GATE_SNAPSHOT_BEFORE"]), rdir / "snapshot-before")
        self.assertEqual(Path(env["GATE_SNAPSHOT_AFTER"]), rdir / "snapshot-after-rollback")

    def test_rest_after_rollback_unnoticed_without_check(self):
        # Ohne post_rollback reicht dem Gate der leere Plan (Live-Test 20.10.2026).
        self._sticky_field_branch()
        hooks, _ = self._rollback_hooks(post_apply_fails=True)
        del hooks["post_rollback"]
        [run] = self._runner(hooks=hooks).run_once()
        self.assertEqual(run.status, "rolled_back", run.reasons)
        self.assertEqual(self._ctl()['unifi_dns_record.this["host-1"]']["comment"], "vom Agenten")

    def test_rest_after_rollback_detected(self):
        self._sticky_field_branch()
        hooks, _ = self._rollback_hooks(post_apply_fails=True)
        [run] = self._runner(hooks=hooks).run_once()
        self.assertEqual(run.status, "rollback_failed", run.reasons)
        self.assertTrue(any("weicht ab" in r and 'this["host-1"]' in r for r in run.reasons), run.reasons)
        self.assertEqual(self._ctl()['unifi_dns_record.this["host-1"]']["comment"], "vom Agenten")
        self.assertTrue(self.cfg.stop_file.exists())
        self.assertTrue(any("Rollback fehlgeschlagen" in n for n in self.approver.notes))
        self.assertIn(run.run_id, self.deadman.cancelled)
        self.assertIn("desired/sticky", self._branches())

    def test_rollback_check_without_snapshot_before_fails(self):
        hooks, _ = self._rollback_hooks()
        runner = self._runner(hooks=hooks)
        runner.d.git.ensure_clone()
        run = Run(run_id="r1", branch="desired/x", head="0" * 40, status="applying",
                  last_good=git("rev-parse", "main", cwd=self.origin))
        run.save(self.cfg.runs_dir)
        run = runner.rollback("r1")
        self.assertEqual(run.status, "rollback_failed")
        self.assertTrue(any("Snapshot vor dem Apply fehlt" in r for r in run.reasons), run.reasons)

    def test_crash_during_apply_recovered_by_deadman(self):
        rec = {"name": "crash.auto.example", "record_type": "A", "value": "CRASH"}
        self._push_branch("desired/crash", self._with("crash", rec))
        with self.assertRaises(Crash):
            self.runner.run_once()
        [run_id] = self.deadman.scheduled
        self.assertEqual(Run.load(self.cfg.runs_dir, run_id).status, "applying")
        self.assertIn('unifi_dns_record.this["crash"]', self._ctl())
        # Das täte der systemd-Timer nach Ablauf:
        run = self._runner().rollback(run_id)
        self.assertEqual(run.status, "rolled_back", run.reasons)
        self.assertNotIn('unifi_dns_record.this["crash"]', self._ctl())

    def test_rollback_for_finished_run_is_noop(self):
        rec = {"name": "h.auto.example", "record_type": "A", "value": "198.51.100.9"}
        self._push_branch("desired/h", self._with("h", rec))
        [run] = self.runner.run_once()
        self.assertEqual(self.runner.rollback(run.run_id).status, "applied")
        self.assertIn('unifi_dns_record.this["h"]', self._ctl())

    def test_main_moved_meanwhile_still_merges(self):
        rec = {"name": "h.auto.example", "record_type": "A", "value": "198.51.100.9"}
        self._push_branch("desired/h", self._with("h", rec))
        # Ein Snapshot-Commit landet auf main, nachdem der Agent gepusht hat.
        other = self.tmp / "snap"
        git("clone", "-q", str(self.origin), str(other), cwd=self.tmp)
        (other / "state").mkdir()
        (other / "state" / "x.yaml").write_text("a: 1\n")
        git("add", "-A", cwd=other)
        git("commit", "-q", "-m", "snapshot", cwd=other)
        git("push", "-q", "origin", "HEAD:main", cwd=other)
        [run] = self.runner.run_once()
        self.assertEqual(run.status, "applied", run.reasons)
        self.assertIn("h", self._main_data()["dns_records"])
        self.assertIn("a: 1", git("show", "main:state/x.yaml", cwd=self.origin))

    def test_delete_is_auto_for_allowed_type(self):
        self._push_branch("desired/del", {"dns_records": {}})
        [run] = self.runner.run_once()
        self.assertEqual(run.status, "applied", run.reasons)
        self.assertEqual(self._ctl(), {})

    def test_run_files_are_redacted(self):
        key = "-----BEGIN PRIVATE KEY-----\nMIIEv\n-----END PRIVATE KEY-----"
        self.approver.answer = False
        self._push_branch("desired/k", self._with("k", {"name": "k.example", "value": key}))
        [run] = self.runner.run_once()
        text = (self.cfg.runs_dir / f"{run.run_id}.json").read_text()
        self.assertNotIn("MIIEv", text)


if __name__ == "__main__":
    unittest.main()
