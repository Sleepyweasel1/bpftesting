Status: needs-triage
Type: AFK

# Seed a testable ScaleToZero fixture in vind

## What to build

Add a minimal in-cluster fixture to the repo-owned `vind` environment so later verification slices have a stable target to exercise without inventing test setup ad hoc. The fixture should include a target Deployment, its Service, and a `ScaleToZero` resource wired to that target, plus a smoke check showing the fixture can be applied successfully in the environment.

## Acceptance criteria

- [ ] A repo-owned command, task, or manifest set applies a minimal target Deployment, Service, and `ScaleToZero` resource in the `vind` environment.
- [ ] The fixture uses the project's current `ScaleToZero` CRD shape and naming conventions.
- [ ] A smoke check confirms the fixture resources are accepted by the cluster and reach a ready state appropriate for future tests.
- [ ] The slice does not assert scale-to-zero behavior; it only provides a stable fixture inside the test environment.

## Blocked by

- .scratch/vind-operator-daemonset-test-environment/issues/02-deploy-scaletozero-control-plane-into-vind.md