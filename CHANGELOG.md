# Changelog

## 0.1.0 (unreleased)

- Policy engine on `tofu show -json` with `auto`, `approval`, `reject`, limits, forbidden rules, provider checks
- Telegram approval bound to the plan hash, single use, persistent replay protection
- Runner: branch polling, path and variable allowlists, plan, hooks, apply, health checks, merge
- Dead-man switch via `systemd-run`, automatic rollback to the last good commit, STOP file on failed rollback
