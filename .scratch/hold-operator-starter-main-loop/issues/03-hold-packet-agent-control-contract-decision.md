# Hold-packet agent control contract decision

Status: needs-triage
Type: AFK

## What to build

Define the operator-to-agent control contract for hold-operator and hold-packet integration. Capture request and response shape, idempotency expectations, timeout and retry behavior, and failure semantics so implementation can proceed predictably.

## Acceptance criteria

- [ ] The control contract for hold-operator to hold-packet interaction is documented in the issue as a concrete proposal.
- [ ] The contract defines behavior for success, timeout, transient failure, and permanent failure.
- [ ] The agreed contract can be implemented without introducing ambiguous behavior in reconcile.

## Blocked by

- .scratch/hold-operator-starter-main-loop/issues/01-starter-controller-runtime-and-reconcile-loop.md
