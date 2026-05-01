Status: needs-triage

# Trigger Replay from staged-packet events after scale-up

## What to build

Wire the Staging Area notification channel into the Reconciler's wake-up path. After a scale-up transition causes `remove_rule`, the Reconciler subscribes to `StagedEvent` notifications from the hold-packet daemon (via a new `WatchStagedPackets` streaming gRPC RPC or by polling `ListRules` and comparing against a local staging cache) and calls `replay_rule(id)` for each Staged Packet belonging to the newly-woken IP. The daemon removes the Staged Packet on successful replay.

End-to-end: a TCP SYN arrives for a held IP → gets staged → Deployment scales back up → Reconciler detects staging event → calls `ReplayRule(id)` → daemon writes frame to TAP → kernel delivers packet to woken pod.

## Acceptance criteria

- [ ] A streaming `WatchStagedPackets` RPC (or equivalent push mechanism) is added to `CapturelistService` proto and implemented in `grpc.rs`, backed by the `Replayer` broadcast channel.
- [ ] `CaptureControl` trait gains a `watch_staged() -> impl Stream<Item=StagedEvent>` method; `HoldPacketClient` and `FakeCaptureControl` implement it.
- [ ] The Reconciler calls `replay_rule` for each `StagedEvent` whose `dst_ip` matches a recently-woken Captured IP.
- [ ] An integration test stages a synthetic frame, triggers a fake scale-up reconcile, and asserts `replay_rule` is called with the correct ID.
- [ ] If `replay_rule` returns "not found" (packet pruned), the error is logged and skipped — not retried.

## Blocked by

- `.scratch/staged-packet-events/issues/01-staged-packet-events.md`
- `.scratch/operator-grpc-adapter/issues/02-reconciler-capture-membership.md`
