# Changelog

## Unreleased

- `recover` command and hook phase: after a failed rollback a timer re-plans main once per STOP; empty plan plus a passing `recover` hook lifts the STOP automatically (copy kept in `state_dir`), otherwise one Telegram approval (Accept re-applies main and lifts it, Decline keeps it). Manual STOP files are never touched
- `discard_pending_on_stop` (default on): after a failed rollback all branches still waiting get status `discarded` and are named in the STOP notification. They were written against a state that no longer holds; after the STOP only a new commit runs them
- `max_branches_per_run` (default 0 = all): `run-once` processes at most this many branches and then releases the lock, so other services sharing the lock do not wait behind a whole queue
- No "applied" notification, neither after a human approval nor for auto changes: success is the expected outcome, failures, rejections, rollbacks and unmerged applies are still reported

## 0.1.0 - 2026-10-20

First public release.


- Policy engine on `tofu show -json` with `auto`, `approval`, `reject`, limits, forbidden rules, provider checks
- Telegram approval bound to the plan hash, single use, persistent replay protection
- Runner: branch polling, path and variable allowlists, plan, hooks, apply, health checks, merge
- Dead-man switch via `systemd-run`, automatic rollback to the last good commit, STOP file on failed rollback
- Optional `post_rollback` hook: fresh snapshot after the rollback compared with the snapshot before the apply, because an empty re-plan misses fields the provider does not reset
- Content-aware three-way merge for `*.tfvars.json`: parallel branches that add different entries to the same file no longer fail with a git conflict; a real conflict names the entry
- `notify` command with per-key throttling, meant for systemd `OnFailure=` of related services
- Only the last `keep_work_dirs` (default 30) work directories of finished runs are kept
- Dead-man timer is re-armed before an in-process rollback
- Approvable hook findings: a `pre_apply` violation with `"severity": "approve"` (hook exit 0) forces a Telegram approval with a warning, also for changes that would be `auto`; after approval the findings go to `post_apply` as `GATE_APPROVED_WARNINGS`
