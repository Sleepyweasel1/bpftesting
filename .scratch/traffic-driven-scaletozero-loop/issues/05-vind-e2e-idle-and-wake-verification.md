Status: needs-triage
Labels: enhancement, needs-triage

# Vind End-to-End Verification for Idle-Down and Wake-Up

## What to build

Add a repeatable vind verification flow that proves both idle-driven scale-down and traffic-driven wake-up/replay behavior for a ScaleToZero target with objective pass/fail output and debugging diagnostics.

End-to-end: fixture starts active -> traffic goes idle and deployment scales to 0 -> synthetic/new traffic triggers wake -> deployment scales to 1 and replay succeeds -> verification command reports success.

## Acceptance criteria

- [ ] A repo-owned command/task runs the full idle-down then wake-up scenario in vind and fails loudly on contract violations.
- [ ] Assertions cover ScaleToZero status contract fields and observable Deployment replica transitions.
- [ ] Failure output includes enough cluster diagnostics (resource/status/log snippets) to debug in CI/local runs.

## Blocked by

- .scratch/traffic-driven-scaletozero-loop/issues/03-idle-driven-scale-down-slice.md
- .scratch/traffic-driven-scaletozero-loop/issues/04-traffic-driven-wake-and-replay-slice.md
