Status: needs-triage

# Reconcile ScaleToZero to Captured IP membership

## What to build

Implement the Reconciler control logic in `hold-operator`. When a `ScaleToZero` event fires, the Reconciler must: (1) look up the target Deployment's associated Service ClusterIP(s) from the Kubernetes API, (2) check the Deployment's current replica count, (3) call `CaptureControl::add_rule` for each ClusterIP when replicas == 0, or `CaptureControl::remove_rule` when replicas > 0. Update `ScaleToZeroStatus` with current replica count and timestamp.

End-to-end: a `ScaleToZero` CR targeting a Deployment at 0 replicas causes the Reconciler to call `AddRule(clusterIP)` on the hold-packet daemon; scaling the Deployment to 1 replica causes `RemoveRule(clusterIP)` — observable by querying `ListRules` on the daemon.

## Acceptance criteria

- [ ] Reconciler resolves the Deployment's Service ClusterIPs from the Kubernetes API (Service selector matching).
- [ ] `add_rule` is called for each ClusterIP when replica count transitions to 0; `remove_rule` is called when count transitions to > 0.
- [ ] `ScaleToZeroStatus.replicas` and `last_updated` are written after each reconcile.
- [ ] A unit test using `FakeCaptureControl` (from the adapter issue) and a mock Kubernetes API verifies both the scale-down and scale-up paths.
- [ ] Reconciler handles Service-not-found and gRPC errors gracefully (requeue with backoff).

## Blocked by

- `.scratch/operator-grpc-adapter/issues/01-operator-grpc-adapter.md`
