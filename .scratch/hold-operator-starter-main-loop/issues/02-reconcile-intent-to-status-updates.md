# Reconcile intent to status updates

Status: needs-triage
Type: AFK

## What to build

Extend reconcile so each run computes current intent for the ScaleToZero resource and writes status updates. This makes operator behavior externally visible and allows maintainers to verify progress from the resource status.

## Acceptance criteria

- [ ] Reconcile updates ScaleToZero status fields on successful processing.
- [ ] Status updates include enough information to distinguish no-op, success, and recoverable failure paths.
- [ ] Repeated reconciles are idempotent and do not produce unnecessary status churn.

## Blocked by

- .scratch/hold-operator-starter-main-loop/issues/01-starter-controller-runtime-and-reconcile-loop.md
