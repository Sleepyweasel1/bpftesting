Status: needs-triage

# Emit Staged Packet events from the Staging Area

## What to build

Add an internal notification channel to `Replayer` so that every time `read_and_stage` stores a Staged Packet it sends a `StagedEvent { id: u64, src_ip: IpAddr, dst_ip: IpAddr }` on a `tokio::sync::broadcast` sender. `Replayer::subscribe()` returns a receiver. The existing TAP read loop and staging logic are unchanged; the channel is additive.

End-to-end: a Staged Packet arrives on the TAP device → `read_and_stage` stages it and sends a `StagedEvent` → any subscriber (operator future, metrics, test) receives the event without accessing the internal `staged` map.

## Acceptance criteria

- [ ] `Replayer` exposes a `subscribe() -> broadcast::Receiver<StagedEvent>` method.
- [ ] `read_and_stage` sends a `StagedEvent` for every successfully staged packet; send errors (no receivers) are silently ignored.
- [ ] A unit test subscribes, stages a synthetic frame, and asserts the event carries the correct `id`, `src_ip`, and `dst_ip`.
- [ ] `CONTEXT.md` is updated to reference `StagedEvent` as the observable output of the Staging Area.

## Blocked by

None — can start immediately.
