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
from types import SimpleNamespace

try:
    import fcntl
except ImportError:  # Windows: kein flock, proc.file_lock sperrt dort nicht
    fcntl = None

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
    "rules": [{"level": "auto", "type": "unifi_dns_record", "where": {"name": {"regex": r".*\.auto\.example"}}},
              {"level": "review", "type": "unifi_dns_record", "where": {"name": {"regex": r".*\.review\.example"}}}],
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
    note: str = ""


class FakeApprover:
    def __init__(self, answer=True):
        self.answer = answer
        self.requests = []
        self.notes = []
        self.on_notify = None

    def request(self, **kw):
        self.requests.append(kw)
        return Res(self.answer, "accepted" if self.answer else "declined")

    def notify(self, text):
        self.notes.append(text)
        if self.on_notify:
            self.on_notify(text)


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
        self.assertEqual(self.approver.notes, [])  # keine Erfolgsmeldung, auch ohne Freigabe

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

    def test_review_level_asks_with_delegate(self):
        rec = {"name": "host-3.review.example", "record_type": "A", "value": "198.51.100.4"}
        self._push_branch("desired/review", self._with("host-3", rec))
        [run] = self.runner.run_once()
        self.assertEqual(run.status, "applied", run.reasons)
        self.assertEqual(run.level, "review")
        self.assertTrue(self.approver.requests[0]["delegate"])

    def test_approval_level_never_delegates(self):
        rec = {"name": "other.example", "record_type": "A", "value": "198.51.100.3"}
        self._push_branch("desired/other", self._with("other", rec))
        self.runner.run_once()
        self.assertFalse(self.approver.requests[0]["delegate"])

    def test_delegate_denial_note_reaches_run_and_message(self):
        rec = {"name": "host-3.review.example", "record_type": "A", "value": "198.51.100.4"}
        self.approver.request = lambda **kw: Res(False, "delegate_denied", "r", "passt zu keinem Auftrag")
        self._push_branch("desired/review", self._with("host-3", rec))
        [run] = self.runner.run_once()
        self.assertEqual(run.status, "declined")
        self.assertIn("delegate_denied: passt zu keinem Auftrag", run.reasons)
        self.assertIn("vom Prüfer abgelehnt", self.approver.notes[-1])
        self.assertIn("passt zu keinem Auftrag", self.approver.notes[-1])

    def test_approval_accepted_applies(self):
        rec = {"name": "other.example", "record_type": "A", "value": "198.51.100.3"}
        self._push_branch("desired/other", self._with("other", rec))
        [run] = self.runner.run_once()
        self.assertEqual(run.status, "applied", run.reasons)
        self.assertEqual(run.level, "approval")
        self.assertEqual(self.approver.notes, [])  # nach Freigabe keine Erfolgsmeldung

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
        # Dead-Man: beim Apply geplant, vor dem Rollback neu geplant, am Ende abgebrochen
        self.assertEqual(self.deadman.scheduled, [run.run_id, run.run_id])
        self.assertEqual(self.deadman.cancelled, [run.run_id, run.run_id])

    def test_rollback_continues_if_deadman_cannot_be_rearmed(self):
        def schedule(run_id):
            if self.deadman.scheduled:
                raise RuntimeError("systemd-run fehlgeschlagen")
            self.deadman.scheduled.append(run_id)
        self.deadman.schedule = schedule
        rec = {"name": "fail.auto.example", "record_type": "A", "value": "FAIL_APPLY"}
        self._push_branch("desired/fail", self._with("fail", rec))
        [run] = self._runner().run_once()
        self.assertEqual(run.status, "rolled_back", run.reasons)
        self.assertNotIn('unifi_dns_record.this["fail"]', self._ctl())

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

    def _warning_hooks(self):
        """pre_apply meldet einen freigebbaren Verstoß, post_apply protokolliert die Übergabe."""
        log = self.tmp / "post_apply.json"
        warning = {"id": "new-source", "message": "neue Quelle", "severity": "approve",
                   "title": "Neuer Zugang zu **git**", "exception": {"invariant": "x", "entry": {}}}
        hooks = {
            "pre_apply": self._hook_script("pre_warn", f"""
                import json
                print(json.dumps({{"ok": True, "violations": [{warning!r}, {warning!r}]}}))
            """),
            "post_apply": self._hook_script("post_warn", f"""
                import json, os
                path = os.environ.get("GATE_APPROVED_WARNINGS")
                json.dump(json.load(open(path)) if path else None, open({str(log)!r}, "w"))
            """),
        }
        return hooks, log, warning

    def test_approvable_warning_turns_auto_into_approval(self):
        hooks, log, warning = self._warning_hooks()
        runner = self._runner(hooks=hooks)
        rec = {"name": "host-2.auto.example", "record_type": "A", "value": "198.51.100.2"}
        self._push_branch("desired/warn", self._with("host-2", rec))
        [run] = runner.run_once()
        self.assertEqual(run.status, "applied", run.reasons)
        self.assertEqual(run.level, "approval")
        [req] = self.approver.requests
        self.assertEqual(req["summary"].count("⚠️ **Achtung:** Neuer Zugang zu **git**"), 1)
        self.assertEqual(json.loads(log.read_text()), [warning, warning])

    def test_declined_warning_not_applied(self):
        hooks, log, _ = self._warning_hooks()
        self.approver.answer = False
        runner = self._runner(hooks=hooks)
        rec = {"name": "host-2.auto.example", "record_type": "A", "value": "198.51.100.2"}
        self._push_branch("desired/warn", self._with("host-2", rec))
        [run] = runner.run_once()
        self.assertEqual(run.status, "declined")
        self.assertNotIn('unifi_dns_record.this["host-2"]', self._ctl())
        self.assertFalse(log.exists())

    def test_no_warning_no_approved_file(self):
        hooks, log, _ = self._warning_hooks()
        hooks["pre_apply"] = self._hook_script("pre_ok", 'print("{}")')
        runner = self._runner(hooks=hooks)
        rec = {"name": "host-2.auto.example", "record_type": "A", "value": "198.51.100.2"}
        self._push_branch("desired/ok", self._with("host-2", rec))
        [run] = runner.run_once()
        self.assertEqual((run.status, run.level), ("applied", "auto"))
        self.assertIsNone(json.loads(log.read_text()))
        self.assertEqual(self.approver.requests, [])

    def test_failed_hook_warnings_are_not_warnings(self):
        hooks, _, warning = self._warning_hooks()
        hooks["pre_apply"] = self._hook_script("pre_fail", f"""
            import json, sys
            print(json.dumps({{"ok": False, "violations": [{warning!r}]}}))
            sys.exit(1)
        """)
        runner = self._runner(hooks=hooks)
        rec = {"name": "host-2.auto.example", "record_type": "A", "value": "198.51.100.2"}
        self._push_branch("desired/fail", self._with("host-2", rec))
        [run] = runner.run_once()
        self.assertEqual(run.status, "rejected")
        self.assertEqual(self.approver.requests, [])

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

    def test_rollback_failed_discards_waiting_branches(self):
        # Live 23.10.2026: Agenten pushten weiter, nach dem STOP wäre die Warteschlange durchgelaufen.
        self._sticky_field_branch()
        rec = {"name": "host-2.auto.example", "record_type": "A", "value": "198.51.100.2"}
        self._push_branch("desired/zz-later", self._with("host-2", rec))
        hooks, _ = self._rollback_hooks(post_apply_fails=True)
        [run] = self._runner(hooks=hooks).run_once()
        self.assertEqual(run.status, "rollback_failed", run.reasons)
        runs = [Run.load(self.cfg.runs_dir, p.stem) for p in self.cfg.runs_dir.glob("*.json")]
        [later] = [r for r in runs if r.branch == "desired/zz-later"]
        self.assertEqual(later.status, "discarded")
        self.assertIn("neuen Commit", later.reasons[-1])
        self.assertTrue(any("Verworfen" in n and "desired/zz-later" in n for n in self.approver.notes))
        self.assertNotIn('unifi_dns_record.this["host-2"]', self._ctl())
        # Nach dem Aufheben des STOP läuft der alte Commit nicht, ein neuer schon.
        self.cfg.stop_file.unlink()
        runner = self._runner(hooks={})
        self.assertEqual(runner.run_once(), [])
        self._push_branch("desired/zz-later", self._with("host-2", dict(rec, value="198.51.100.3")))
        [again] = runner.run_once()
        self.assertEqual((again.branch, again.status), ("desired/zz-later", "applied"), again.reasons)

    def test_rollback_failed_keeps_waiting_branches_when_disabled(self):
        self.cfg.discard_pending_on_stop = False
        self._sticky_field_branch()
        rec = {"name": "host-2.auto.example", "record_type": "A", "value": "198.51.100.2"}
        self._push_branch("desired/zz-later", self._with("host-2", rec))
        hooks, _ = self._rollback_hooks(post_apply_fails=True)
        [run] = self._runner(hooks=hooks).run_once()
        self.assertEqual(run.status, "rollback_failed", run.reasons)
        self.cfg.stop_file.unlink()
        [later] = self._runner(hooks={}).run_once()
        self.assertEqual((later.branch, later.status), ("desired/zz-later", "applied"), later.reasons)

    # ---------------------------------------------------------------- Wiederanlauf nach STOP

    def _stopped(self, recover_ok=True):
        """rollback_failed (Feld bleibt nach dem Rollback stehen), dazu ein recover-Hook."""
        self._sticky_field_branch()
        hooks, _ = self._rollback_hooks(post_apply_fails=True)
        [run] = self._runner(hooks=hooks).run_once()
        self.assertEqual(run.status, "rollback_failed", run.reasons)
        hooks["recover"] = self._hook_script("recover", f"""
            import json, os, sys
            assert os.environ["GATE_PHASE"] == "recover"
            assert os.path.isdir(os.environ["GATE_SNAPSHOT_BEFORE"])
            assert os.path.isfile(os.path.join(os.environ["GATE_SNAPSHOT_AFTER"], "controller.json"))
            ok = {recover_ok!r}
            print(json.dumps({{"ok": ok, "violations": [
                {{"id": "unexpected-change", "message": "Policy p verschwunden" if not ok else "Feld comment"}}]}}))
            sys.exit(0 if ok else 1)
        """)
        return run, self._runner(hooks=hooks)

    def test_recover_resumes_when_main_matches(self):
        run, runner = self._stopped()
        self.approver.requests.clear()
        self.assertEqual(runner.recover(), "resumed")
        self.assertFalse(self.cfg.stop_file.exists())
        [copy] = self.cfg.state_dir.glob(f"STOP-*-{run.run_id}.txt")
        self.assertIn(run.run_id, copy.read_text())
        self.assertEqual(self.approver.requests, [])
        self.assertTrue(any("Gate läuft wieder" in n and "Feld comment" in n for n in self.approver.notes))
        self.assertEqual(runner.recover(), "no_stop")

    def test_recover_leaves_manual_stop_alone(self):
        self.cfg.stop_file.write_text("Tobias: Wartung\n")
        self.assertEqual(self.runner.recover(), "manual")
        self.assertTrue(self.cfg.stop_file.exists())

    def test_recover_asks_once_and_keeps_stop_on_decline(self):
        run, runner = self._stopped(recover_ok=False)
        self.approver.answer = False
        self.assertEqual(runner.recover(), "declined")
        self.assertTrue(self.cfg.stop_file.exists())
        [req] = self.approver.requests
        self.assertIn("Policy p verschwunden", req["summary"])
        self.assertIn("Decline: STOP bleibt", req["summary"])
        self.assertEqual(runner.recover(), "declined")
        self.assertEqual(len(self.approver.requests), 1)

    def test_recover_accept_resumes_despite_findings(self):
        run, runner = self._stopped(recover_ok=False)
        self.approver.answer = True
        self.assertEqual(runner.recover(), "resumed")
        self.assertFalse(self.cfg.stop_file.exists())

    def test_recover_timeout_waits_before_asking_again(self):
        run, runner = self._stopped(recover_ok=False)
        self.approver.request = lambda **kw: (self.approver.requests.append(kw), Res(False, "timeout"))[1]
        self.assertEqual(runner.recover(), "waiting")
        self.assertEqual(runner.recover(), "waiting")
        self.assertEqual(len(self.approver.requests), 1)
        self.cfg.recover_reask_hours = 0
        self.assertEqual(runner.recover(), "waiting")
        self.assertEqual(len(self.approver.requests), 2)

    def test_recover_reapplies_main_after_accept(self):
        run, runner = self._stopped()
        ctl = self._ctl()
        ctl['unifi_dns_record.this["rest"]'] = {"name": "rest.auto.example", "record_type": "A", "value": "198.51.100.9"}
        self.controller.write_text(json.dumps(ctl))
        self.approver.requests.clear()
        self.approver.answer = True
        self.assertEqual(runner.recover(), "resumed")
        [req] = self.approver.requests
        self.assertIn("Plan von main nicht leer", req["summary"])
        self.assertNotIn('unifi_dns_record.this["rest"]', self._ctl())
        self.assertFalse(self.cfg.stop_file.exists())

    def _forward_stop(self):
        """Apply durch, Prüfung danach und Rollback gescheitert, Controller hat den Branch-Stand."""
        rec = {"name": "host-2.auto.example", "record_type": "A", "value": "198.51.100.2"}
        self._push_branch("desired/fwd", self._with("host-2", rec))
        hooks, _ = self._rollback_hooks(post_apply_fails=True)
        hooks["post_rollback"] = self._hook_script("post_rb_fail", """
            import json, sys
            print(json.dumps({"ok": False, "violations": [{"id": "x", "message": "weicht ab"}]}))
            sys.exit(1)
        """)
        [run] = self._runner(hooks=hooks).run_once()
        self.assertEqual(run.status, "rollback_failed", run.reasons)
        # Live 23.10.2026: Platte voll, der Rollback kam nie bis zum Controller.
        ctl = self._ctl()
        ctl['unifi_dns_record.this["host-2"]'] = rec
        self.controller.write_text(json.dumps(ctl))
        hooks["recover"] = self._hook_script("recover_fwd", """
            import json, os, sys
            plan = json.load(open(os.environ["GATE_PLAN_JSON"]))
            assert plan["resource_changes"], "beim Übernehmen zählt der Plan des Laufs"
            print(json.dumps({"ok": True, "violations": []}))
        """)
        return run, self._runner(hooks=hooks)

    def test_recover_rolls_forward_when_controller_matches_branch(self):
        run, runner = self._forward_stop()
        self.approver.requests.clear()
        self.assertEqual(runner.recover(), "resumed")
        self.assertEqual(self.approver.requests, [])
        self.assertFalse(self.cfg.stop_file.exists())
        self.assertIn("host-2", self._main_data()["dns_records"])
        self.assertNotIn("desired/fwd", self._branches())
        self.assertEqual(Run.load(self.cfg.runs_dir, run.run_id).status, "applied")
        self.assertTrue(any("nach main übernommen" in n for n in self.approver.notes))

    def test_recover_forward_needs_matching_controller(self):
        run, runner = self._forward_stop()
        ctl = self._ctl()
        ctl['unifi_dns_record.this["host-2"]']["value"] = "198.51.100.99"  # weder main noch Branch
        self.controller.write_text(json.dumps(ctl))
        self.approver.answer = False
        self.assertEqual(runner.recover(), "declined")
        self.assertIn("Accept: main erneut anwenden", self.approver.requests[-1]["summary"])
        self.assertNotIn("host-2", self._main_data()["dns_records"])

    def test_recover_new_stop_is_checked_again(self):
        run, runner = self._stopped(recover_ok=False)
        self.approver.answer = False
        self.assertEqual(runner.recover(), "declined")
        self.cfg.stop_file.write_text(self.cfg.stop_file.read_text() + "zweiter Fehler\n")
        self.assertEqual(runner.recover(), "declined")
        self.assertEqual(len(self.approver.requests), 2)

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

    def test_old_work_dirs_pruned_but_not_running_or_failed(self):
        self.cfg.keep_work_dirs = 2
        wdir = self.cfg.state_dir / "work"
        statuses = ["applied", "applying", "rollback_failed", "rejected", "applied", "declined"]
        ids = []
        for i, status in enumerate(statuses):
            rid = f"20261020T10000{i}-x-{i:08d}"
            Run(run_id=rid, branch="desired/x", head="0" * 40, status=status).save(self.cfg.runs_dir)
            (wdir / rid / "snapshot-before").mkdir(parents=True)
            ids.append(rid)
        (wdir / "fremd").mkdir()  # ohne Lauf-Datei: bleibt
        self.runner.run_once()
        left = sorted(p.name for p in wdir.iterdir())
        self.assertEqual(left, sorted([ids[1], ids[2], ids[4], ids[5], "fremd"]))
        self.assertEqual(len(list(self.cfg.runs_dir.glob("*.json"))), len(statuses))

    def _fake_statvfs(self, free):
        """free: Liste mit einem Wert, damit der Test ihn zwischen den Läufen ändern kann."""
        self.runner.d.statvfs = lambda path: SimpleNamespace(f_blocks=1000, f_bavail=1000, f_files=1000,
                                                             f_favail=int(free[0] * 10))

    def test_low_space_branch_waits_without_apply(self):
        # Live 23.10.2026: Inodes voll, Apply lief, Snapshot und Rollback scheiterten
        rec = {"name": "host-2.auto.example", "record_type": "A", "value": "198.51.100.2"}
        self._push_branch("desired/add-host-2", self._with("host-2", rec))
        free = [4]
        self._fake_statvfs(free)
        self.assertEqual(self.runner.run_once(), [])
        self.assertEqual(self.runner.run_once(), [])
        self.assertNotIn('unifi_dns_record.this["host-2"]', self._ctl())
        self.assertIn("desired/add-host-2", self._branches())
        self.assertEqual(len(self.approver.notes), 1, self.approver.notes)  # nur einmal melden
        self.assertIn("Gate wartet", self.approver.notes[0])
        free[0] = 50
        [run] = self.runner.run_once()
        self.assertEqual(run.status, "applied", run.reasons)
        self.assertIn("wieder 50 % frei", self.approver.notes[1])

    def test_low_space_prunes_old_work_dirs_first(self):
        self.cfg.keep_work_dirs = 10
        wdir = self.cfg.state_dir / "work"
        for i in range(6):
            rid = f"20261020T10000{i}-x-{i:08d}"
            Run(run_id=rid, branch="desired/x", head="0" * 40, status="applied").save(self.cfg.runs_dir)
            (wdir / rid / "snapshot-before").mkdir(parents=True)
        # frei wird es erst, wenn höchstens drei Arbeitsordner übrig sind
        self.runner.d.statvfs = lambda path: SimpleNamespace(
            f_blocks=1000, f_bavail=1000, f_files=1000,
            f_favail=500 if len(list(wdir.iterdir())) <= 3 else 10)
        rec = {"name": "host-2.auto.example", "record_type": "A", "value": "198.51.100.2"}
        self._push_branch("desired/add-host-2", self._with("host-2", rec))
        [run] = self.runner.run_once()
        self.assertEqual(run.status, "applied", run.reasons)
        self.assertEqual(self.approver.notes, [])

    def test_parallel_branches_same_file_merged_by_content(self):
        # Live 21.10.2026: zwei Agenten haengen je einen Eintrag an dieselbe Datei an
        rec_a = {"name": "host-2.auto.example", "record_type": "A", "value": "198.51.100.2"}
        rec_b = {"name": "host-3.auto.example", "record_type": "A", "value": "198.51.100.3"}
        self._push_branch("desired/a", self._with("host-2", rec_a))
        self._push_branch("desired/b", self._with("host-3", rec_b))
        runs = self.runner.run_once()
        self.assertEqual([r.status for r in runs], ["applied", "applied"], [r.reasons for r in runs])
        self.assertEqual(set(self._main_data()["dns_records"]), {"host-1", "host-2", "host-3"})
        self.assertEqual(self._ctl()['unifi_dns_record.this["host-3"]'], rec_b)

    def test_max_branches_per_run_leaves_rest_for_next_run(self):
        rec_a = {"name": "host-2.auto.example", "record_type": "A", "value": "198.51.100.2"}
        rec_b = {"name": "host-3.auto.example", "record_type": "A", "value": "198.51.100.3"}
        self._push_branch("desired/a", self._with("host-2", rec_a))
        self._push_branch("desired/b", self._with("host-3", rec_b))
        self.cfg.max_branches_per_run = 1
        [first] = self.runner.run_once()
        self.assertEqual((first.branch, first.status), ("desired/a", "applied"), first.reasons)
        self.assertEqual(set(self._main_data()["dns_records"]), {"host-1", "host-2"})
        [second] = self.runner.run_once()
        self.assertEqual((second.branch, second.status), ("desired/b", "applied"), second.reasons)
        self.assertEqual(self.runner.run_once(), [])
        self.assertEqual(set(self._main_data()["dns_records"]), {"host-1", "host-2", "host-3"})

    def test_pending_only_while_branches_left(self):
        rec_a = {"name": "host-2.auto.example", "record_type": "A", "value": "198.51.100.2"}
        rec_b = {"name": "host-3.auto.example", "record_type": "A", "value": "198.51.100.3"}
        self._push_branch("desired/a", self._with("host-2", rec_a))
        self._push_branch("desired/b", self._with("host-3", rec_b))
        self.cfg.max_branches_per_run = 1
        self.runner.run_once()
        self.assertTrue(self.runner.pending)
        self.runner.run_once()
        self.assertFalse(self.runner.pending)
        self.runner.run_once()
        self.assertFalse(self.runner.pending)

    def test_pending_counts_branch_pushed_during_approval(self):
        # Ein Agent pusht, während der Lauf auf die Freigabe wartet: gleich weitermachen.
        rec_a = {"name": "host-2.example", "record_type": "A", "value": "198.51.100.2"}
        rec_b = {"name": "host-3.auto.example", "record_type": "A", "value": "198.51.100.3"}
        self._push_branch("desired/a", self._with("host-2", rec_a))
        request = self.approver.request

        def approve_and_push(**kw):
            self._push_branch("desired/b", self._with("host-3", rec_b))
            return request(**kw)

        self.approver.request = approve_and_push
        self.cfg.max_branches_per_run = 1
        [run] = self.runner.run_once()
        self.assertEqual(run.status, "applied", run.reasons)
        self.assertTrue(self.runner.pending)

    def test_no_pending_after_stop(self):
        rec_a = {"name": "host-2.auto.example", "record_type": "A", "value": "198.51.100.2"}
        rec_b = {"name": "host-3.auto.example", "record_type": "A", "value": "198.51.100.3"}
        self._push_branch("desired/a", self._with("host-2", rec_a))
        self._push_branch("desired/b", self._with("host-3", rec_b))
        self.cfg.max_branches_per_run = 1
        orig = self.runner.process

        def process_then_stop(br):
            run = orig(br)
            self.cfg.stop_file.write_text("test")
            return run

        self.runner.process = process_then_stop
        self.runner.run_once()
        self.assertFalse(self.runner.pending)

    def _two_auto_branches(self):
        rec_a = {"name": "host-2.auto.example", "record_type": "A", "value": "198.51.100.2"}
        rec_b = {"name": "host-3.auto.example", "record_type": "A", "value": "198.51.100.3"}
        self._push_branch("desired/a", self._with("host-2", rec_a))
        self._push_branch("desired/b", self._with("host-3", rec_b))
        self.cfg.max_branches_per_run = 1
        self.cfg.drain_minutes = 20
        self.pauses = []
        self.runner.d.sleep = self.pauses.append

    def test_drain_works_off_queue_with_lock_pause(self):
        self._two_auto_branches()
        runs = self.runner.run_once()
        self.assertEqual([(r.branch, r.status) for r in runs],
                         [("desired/a", "applied"), ("desired/b", "applied")], [r.reasons for r in runs])
        self.assertEqual(self.pauses, [15])  # nur zwischen zwei Branches, nicht am Ende
        self.assertFalse(self.runner.pending)

    def test_drain_stops_after_budget(self):
        self._two_auto_branches()
        ticks = iter(range(0, 10**6, 600))  # jede Uhrabfrage 10 min später
        self.runner.d.clock = lambda: float(next(ticks))
        [run] = self.runner.run_once()
        self.assertEqual(run.branch, "desired/a")
        self.assertTrue(self.runner.pending)
        self.assertEqual(self.pauses, [])

    @unittest.skipUnless(fcntl, "flock nur unter Unix")
    def test_drain_yields_when_other_service_takes_lock(self):
        self._two_auto_branches()
        held = []

        def other_service_grabs_lock(_seconds):
            fd = open(self.cfg.lock_file, "a")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            held.append(fd)

        self.runner.d.sleep = other_service_grabs_lock
        try:
            [run] = self.runner.run_once()
        finally:
            for fd in held:
                fd.close()
        self.assertEqual(run.branch, "desired/a")
        self.assertEqual(len(held), 1)

    def test_drain_stops_on_stop_file(self):
        self._two_auto_branches()
        self.runner.d.sleep = lambda _s: self.cfg.stop_file.write_text("test")
        [run] = self.runner.run_once()
        self.assertEqual(run.branch, "desired/a")

    def test_real_conflict_names_the_entry(self):
        a = {"name": "host-1.auto.example", "record_type": "A", "value": "198.51.100.7"}
        b = {"name": "host-1.auto.example", "record_type": "A", "value": "198.51.100.8"}
        self._push_branch("desired/a", self._with("host-1", a))
        self._push_branch("desired/b", self._with("host-1", b))
        runs = {r.branch: r for r in self.runner.run_once()}
        self.assertEqual(runs["desired/a"].status, "applied")
        self.assertEqual(runs["desired/b"].status, "rejected")
        self.assertIn("/dns_records/host-1/value", runs["desired/b"].reasons[-1])

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

    def test_second_branch_planned_on_merged_first(self):
        # Beide Branches entstehen vom selben main. B muss gegen main mit A geplant werden,
        # sonst nimmt der Apply von B den Eintrag aus A wieder weg.
        rec_a = {"name": "host-2.auto.example", "record_type": "A", "value": "198.51.100.2"}
        rec_b = {"name": "host-3.auto.example", "record_type": "A", "value": "198.51.100.3"}
        self._push_branch("desired/a", self._with("host-2", rec_a))
        git("checkout", "-q", "-B", "desired/b", "origin/main", cwd=self.agent)
        (self.agent / "tofu" / "dns-b.auto.tfvars.json").write_text(json.dumps({"dns_records": {"host-3": rec_b}}))
        git("add", "-A", cwd=self.agent)
        git("commit", "-q", "-m", "Agent: host-3", cwd=self.agent)
        git("push", "-q", "origin", "HEAD:refs/heads/desired/b", cwd=self.agent)
        runs = self.runner.run_once()
        self.assertEqual([r.status for r in runs], ["applied", "applied"], [r.reasons for r in runs])
        self.assertEqual(self._ctl()['unifi_dns_record.this["host-2"]'], rec_a)
        self.assertEqual(self._ctl()['unifi_dns_record.this["host-3"]'], rec_b)
        self.assertIn("host-2", self._main_data()["dns_records"])
        self.assertEqual(runs[1].last_good, git("rev-parse", "main^", cwd=self.origin))

    def test_main_moved_between_branches_is_fetched(self):
        # Nach Branch A landet von außen ein weiterer Eintrag auf main. B muss darauf aufsetzen.
        rec_a = {"name": "host-2.auto.example", "record_type": "A", "value": "198.51.100.2"}
        rec_b = {"name": "host-3.auto.example", "record_type": "A", "value": "198.51.100.3"}
        rec_x = {"name": "host-9.auto.example", "record_type": "A", "value": "198.51.100.9"}
        self._push_branch("desired/a", self._with("host-2", rec_a))
        git("checkout", "-q", "-B", "desired/b", "origin/main", cwd=self.agent)
        (self.agent / "tofu" / "dns-b.auto.tfvars.json").write_text(json.dumps({"dns_records": {"host-3": rec_b}}))
        git("add", "-A", cwd=self.agent)
        git("commit", "-q", "-m", "Agent: host-3", cwd=self.agent)
        git("push", "-q", "origin", "HEAD:refs/heads/desired/b", cwd=self.agent)
        other = self.tmp / "human"

        finish = self.runner._finish

        def human_pushes(run, status, *args, **kwargs):
            # Erfolg wird nicht gemeldet, also direkt nach dem Abschluss von A einhaken.
            result = finish(run, status, *args, **kwargs)
            if run.branch == "desired/a" and status == "applied" and not other.exists():
                git("clone", "-q", str(self.origin), str(other), cwd=self.tmp)
                (other / "tofu" / "dns-x.auto.tfvars.json").write_text(json.dumps({"dns_records": {"host-9": rec_x}}))
                git("add", "-A", cwd=other)
                git("commit", "-q", "-m", "von Hand", cwd=other)
                git("push", "-q", "origin", "HEAD:main", cwd=other)
            return result

        self.runner._finish = human_pushes
        runs = self.runner.run_once()
        self.assertEqual([r.status for r in runs], ["applied", "applied"], [r.reasons for r in runs])
        self.assertEqual(runs[1].last_good, git("rev-parse", "HEAD", cwd=other))
        self.assertEqual(set(self._ctl()), {f'unifi_dns_record.this["{k}"]' for k in ("host-1", "host-2", "host-3", "host-9")})

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
