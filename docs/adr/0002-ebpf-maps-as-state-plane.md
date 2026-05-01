# ADR-0002: eBPF Hash Maps as the Shared State Plane

**Status**: Accepted  
**Date**: 2026-05-01

## Context

The eBPF classifier and the userspace daemon both need to read and write the
state of each Captured IP (Capture Mode, last-seen timestamp, packet count).
Options include: eBPF hash maps (pinned or fd-passed), perf/ring-buffer events
from kernel to userspace, or a userspace-only copy.

## Decision

Use **eBPF `HashMap` maps** (`STATEV4`, `STATEV6`) as the shared state plane.
The daemon holds `MapData` handles (via `aya::maps::HashMap`) wrapped in
`Arc<RwLock<>>`. The eBPF program and the userspace daemon read and write the
same kernel memory-mapped region.

## Rationale

- Maps provide synchronous random-access reads from both sides; no message
  queue is needed for the Idle Monitor's polling loop.
- The daemon can insert/remove Captured IPs atomically from the gRPC handler
  without coordinating with the eBPF program via a separate channel.
- Perf/ring-buffer events would deliver per-packet notifications but would
  require a separate state reconciliation mechanism and add per-packet overhead
  for the userspace path.

## Consequences

- The `StateEntry` struct must be `#[repr(C)]` and shared via `hold-packet-common`
  compiled for both `bpfel` (kernel) and the host target.
- Kernel-side map writes from the eBPF classifier and userspace writes from the
  Idle Monitor are not atomic with each other; `last_seen_ns` may be stale by
  up to the 30 s poll interval.
- Map capacity is capped at 1 024 entries per address family. Exceeding this is
  a silent failure (insert returns an error that the gRPC layer returns as
  `Status::internal`).
