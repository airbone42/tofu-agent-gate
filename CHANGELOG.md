# Changelog

## 0.1.0 - 2026-10-20

First public release.


- Policy engine on `tofu show -json` with `auto`, `approval`, `reject`, limits, forbidden rules, provider checks
- Telegram approval bound to the plan hash, single use, persistent replay protection
- Runner: branch polling, path and variable allowlists, plan, hooks, apply, health checks, merge
- Dead-man switch via `systemd-run`, automatic rollback to the last good commit, STOP file on failed rollback
- Optional `post_rollback` hook: fresh snapshot after the rollback compared with the snapshot before the apply, because an empty re-plan misses fields the provider does not reset
- `notify` command with per-key throttling, meant for systemd `OnFailure=` of related services
- Only the last `keep_work_dirs` (default 30) work directories of finished runs are kept
- Dead-man timer is re-armed before an in-process rollback
- Approvable hook findings: a `pre_apply` violation with `"severity": "approve"` (hook exit 0) forces a Telegram approval with a warning, also for changes that would be `auto`; after approval the findings go to `post_apply` as `GATE_APPROVED_WARNINGS`
