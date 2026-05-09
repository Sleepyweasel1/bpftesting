Status: needs-triage
Labels: enhancement, needs-triage

# Idle-Driven Scale-Down Vertical Slice

## What to build

Implement idle-driven scale-down for ScaleToZero targets: when traffic remains idle past the configured threshold, reconcile scales the target Deployment to zero while keeping capture membership aligned so wake traffic can still be staged.

End-to-end: target has no traffic beyond idle window -> operator decides idle -> operator scales deployment to 0 -> capture rules remain armed for target service IPs -> status shows idle-driven decision.

## Acceptance criteria

- [ ] Idle threshold policy is configurable on the ScaleToZero resource or operator config with deterministic defaults.
- [ ] When idle threshold is exceeded, reconcile scales target deployment to 0 and reports `Succeeded` with clear decision message.
- [ ] Integration/unit tests verify no false scale-down during active traffic and successful scale-down after sustained idle period.

## Blocked by

- .scratch/traffic-driven-scaletozero-loop/issues/01-traffic-signal-contract-for-decisions.md
- .scratch/traffic-driven-scaletozero-loop/issues/02-reconciler-scale-action-path.md
