# Security Policy

Please report vulnerabilities privately through GitHub Security Advisories of this repository ("Report a vulnerability" on the Security tab of `<owner>/tofu-agent-gate`). Do not open public issues for security problems.

Scope that matters most: anything that lets an agent branch execute code on the runner, read provider credentials or state, bypass the policy, reuse or forge an approval, or prevent a rollback.

Operational notes:
- Keep the policy, hook configuration, Telegram token and state outside of the repository the agents can write to.
- Run the gate from a release tag. Never run gate code from `main` or an agent branch.
- Repositories containing infrastructure snapshots must stay private.
