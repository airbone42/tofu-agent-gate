# tofu-agent-gate

A small, auditable gate that lets AI agents (or any untrusted automation) propose infrastructure changes to an OpenTofu configuration, and rolls them out without a human in the loop when automatic guardrails allow it.

- Agents push a branch `desired/<topic>`. They never get provider credentials.
- A runner on a trusted host plans the branch, classifies the plan with a policy (`auto`, `approval`, `reject`), optionally asks a human via Telegram (Accept/Decline bound to the plan hash), applies, runs health checks and rolls back automatically on failure.
- A dead-man switch (systemd timer) rolls back even if the runner hangs or crashes mid-apply.

Nothing in here is specific to a provider. It was built for a UniFi network managed with `ubiquiti-community/unifi`, but works with any provider.

Status: early (0.1.0), in daily use on one UniFi homelab. Python 3.13, standard library plus PyYAML.

## Security model

| Threat | Mitigation |
|---|---|
| Agent HCL runs code or leaks credentials during `plan` (foreign providers, provisioners, `backend`, provider arguments) | By default agents may only change data files (`allowed_paths`, e.g. `tofu/*.auto.tfvars.json`). HCL always comes from `main`. Branches touching other paths are rejected before `tofu` runs. |
| Agent sets variables it should not (e.g. the state encryption passphrase) | `allowed_variables`: top-level keys allowed in `*.tfvars.json` |
| Provider supply chain | Runner-owned CLI config with a `filesystem_mirror` and no `direct` block, `init -lockfile=readonly` |
| State leaks | Backend path set by a runner-written override file, state encryption recommended and enforced in HCL |
| Approving something other than what gets applied | Approval is bound to the SHA-256 of the binary plan file, re-checked right before `apply` |
| Replayed or forged Telegram clicks | User ID, chat ID, message ID, open request, expiry and plan hash are all checked, every approval is single-use and persisted |
| Agent text in approval messages | Messages are HTML with every dynamic part escaped. Only the first line of the agent's commit message is shown, separately, marked as unverified and truncated |
| A change is acceptable only as an exception (e.g. new access to a protected zone) | A `pre_apply` hook can report findings with `severity: approve`: the change is never applied automatically, the approval shows each warning, and `post_apply` receives the approved findings |
| Secrets in messages and logs | Plan-sensitive values are masked, plus generic redaction (private keys, tokens) and an optional domain-specific redaction hook |
| Apply breaks connectivity or a provider silently writes something else | Post-apply health checks: empty re-plan, external snapshot diff and invariant hooks, automatic rollback to the last good commit |
| Runner hangs during apply | Dead-man timer (`systemd-run`) kills the run and rolls back |
| Rollback leaves something behind (provider treats null as "keep") | Optional `post_rollback` hook compares a fresh snapshot with the one taken before the apply |
| Rollback itself fails | Runner writes a STOP file and stops processing. Branches still waiting are discarded (`discard_pending_on_stop`), a new commit retries them after the STOP. `recover` (timer) lifts the STOP by itself when main plans empty and the `recover` hook passes on a fresh snapshot, otherwise it asks once via Telegram |

Policies and hook configuration live on the runner host, never in the repository. Run the gate from a release tag, not from a branch.

## How it works

```
agent --push desired/x--> git <--fetch-- runner (systemd timer)
                                           |  path + variable checks
                                           |  tofu plan -out, tofu show -json
                                           |  policy + pre-apply hooks
                                           |  [Telegram approval]
                                           |  dead-man timer, tofu apply
                                           |  re-plan empty? post-apply hooks
                                           '-> merge to main, or roll back
```

See [docs/ARCHITEKTUR.md](docs/ARCHITEKTUR.md) (German) for the full specification of `gate.yaml`, the policy format and the hook interface.

## Install

```bash
pip install "git+https://github.com/airbone42/tofu-agent-gate@v0.1.0"
```

Configuration defaults to `/etc/tofu-agent-gate/gate.yaml`, override with `GATE_CONFIG` or `--config`.

```bash
tofu-agent-gate check-config
tofu-agent-gate classify plan.json --policy policy.yaml   # dry run of the policy
tofu-agent-gate run-once                                   # process new desired/* branches
tofu-agent-gate rollback <run-id>                          # used by the dead-man timer
tofu-agent-gate status
tofu-agent-gate notify "text" --key unit --min-interval 3600   # throttled message, e.g. from systemd OnFailure=
```

## Policy example

```yaml
version: 1
vars:
  auto_zones: ["<zone-id-a>", "<zone-id-b>"]
limits:
  max_changes: 10
  allowed_types: [unifi_dns_record, unifi_firewall_policy]
  allow_delete: [unifi_dns_record]
providers:
  allowed: ["registry.opentofu.org/ubiquiti-community/unifi"]
  forbidden_arguments: [api_url, api_key, allow_insecure]
forbidden:
  - type: unifi_setting
  - references: ["<management-zone-id>"]
rules:
  - level: auto
    type: unifi_dns_record
  - level: auto
    type: unifi_firewall_policy
    actions: [create, update]
    where:
      source.zone_id: {in: "$auto_zones"}
      destination.zone_id: {in: "$auto_zones"}
default: approval
```

A classic invariant to implement as a hook: "segment X may only reach the internet through gateway Y".

## Development

```bash
python -m unittest discover -s tests
```

Tests need `git` but no network, no OpenTofu binary and no Telegram account: OpenTofu, the Telegram Bot API and the controller are faked.

## License

MIT, see [LICENSE](LICENSE).
