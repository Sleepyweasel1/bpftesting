# End-to-end starter verification for scale-to-zero flow

Status: needs-triage
Type: AFK

## What to build

Add a starter end-to-end verification path proving that creating or updating a ScaleToZero resource triggers reconcile and executes the hold-packet interaction path through to observable status updates.

## Acceptance criteria

- [ ] A repeatable verification flow confirms reconcile is triggered by ScaleToZero changes.
- [ ] The verification flow confirms hold-packet interaction is reached through the integrated path.
- [ ] Verification output provides objective pass or fail evidence suitable for CI or local smoke testing.

## Blocked by

- .scratch/hold-operator-starter-main-loop/issues/04-wire-agent-call-in-reconcile-happy-path.md
