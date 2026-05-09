Status: needs-triage
Labels: enhancement, needs-triage

# Traffic-Driven Wake-Up and Replay Vertical Slice

## What to build

Implement wake-up from new traffic while scaled down: when staged traffic is observed for a held target, reconcile scales the Deployment up and replays staged packets for the recently woken service IPs.

End-to-end: staged packet for held destination arrives -> operator triggers scale-up to 1 -> operator removes capture for woken IPs -> operator replays matching staged packets -> status records wake transition outcome.

## Acceptance criteria

- [ ] Reconcile wake path scales target from 0 to 1 on qualifying staged-traffic signal and is idempotent under repeated events.
- [ ] Replay executes for staged packets matching recently-woken destination IPs and tolerates not-found pruning safely.
- [ ] Tests verify wake-up, replay, and status transitions under success and recoverable-failure scenarios.

## Blocked by

- .scratch/traffic-driven-scaletozero-loop/issues/02-reconciler-scale-action-path.md
