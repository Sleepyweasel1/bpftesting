# Wire agent call in reconcile happy path

Status: needs-triage
Type: AFK

## What to build

Implement the hold-operator reconcile path that invokes the hold-packet agent using the agreed control contract. Handle success and failure responses and keep status updates consistent with operator outcomes.

## Acceptance criteria

- [ ] Reconcile invokes hold-packet agent on the happy path using the defined control contract.
- [ ] Agent success and failure outcomes are translated to clear status updates.
- [ ] Recoverable failures are retried through reconcile without breaking idempotency.

## Blocked by

- .scratch/hold-operator-starter-main-loop/issues/02-reconcile-intent-to-status-updates.md
- .scratch/hold-operator-starter-main-loop/issues/03-hold-packet-agent-control-contract-decision.md
