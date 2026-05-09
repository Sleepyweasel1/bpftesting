Status: needs-triage
Labels: enhancement, needs-triage

# Reconciler Scale Action Path (Patch Deployment Scale)

## What to build

Add an idempotent scale-action path in hold-operator so reconcile can patch target Deployment scale up/down when a decision requires it. This slice should include safe retry behavior, status outcomes, and required RBAC updates.

End-to-end: reconcile computes desired replica action -> operator patches Deployment scale subresource -> status reflects succeeded/no-op/recoverable-failure.

## Acceptance criteria

- [ ] hold-operator has a tested API seam for get/patch Deployment scale in target namespace.
- [ ] Reconcile can execute explicit scale-to-0 and scale-to-1 actions idempotently with retryable error handling.
- [ ] Kubernetes manifests/RBAC grant only the minimum permissions required for Deployment scale reads/writes.

## Blocked by

- .scratch/traffic-driven-scaletozero-loop/issues/01-traffic-signal-contract-for-decisions.md
