Status: needs-triage
Type: AFK

# Deploy ScaleToZero control plane into vind

## What to build

Deploy the ScaleToZero control plane into the repo-owned `vind` environment so later integration slices can exercise the Reconciler and the hold-packet daemon together. This slice should package and apply the Kubernetes resources needed to run the `hold-operator`, register the `ScaleToZero` CRD, and run the hold-packet daemon as a DaemonSet, with a smoke verification path that proves the environment is ready for future tests.

## Acceptance criteria

- [ ] A repo-owned command or task deploys the `ScaleToZero` CRD, RBAC, `hold-operator`, and hold-packet DaemonSet into the `vind` environment.
- [ ] The deployment path is repeatable against a freshly created `vind` environment.
- [ ] A smoke check verifies the CRD is registered, the Reconciler is running, and the hold-packet DaemonSet pods are ready.
- [ ] The slice does not add behavior-specific scale-to-zero test cases; it only proves the environment is ready for them.

## Blocked by

- .scratch/vind-operator-daemonset-test-environment/issues/01-vind-cluster-bootstrap-for-hold-packet-dev.md