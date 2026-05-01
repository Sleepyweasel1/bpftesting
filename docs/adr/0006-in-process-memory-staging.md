# ADR-0006: In-Process Memory Staging for Held Packets

**Status**: Accepted  
**Date**: 2026-05-01

## Context

Packets redirected to the TAP device must be held until the operator decides
to replay or discard them. Storage options: in-process `HashMap` (current),
an external queue (Redis, Kafka), a memory-mapped file, or a kernel ring buffer.

## Decision

Stage Staged Packets in an **in-process `HashMap<u64, StagedPacket>`** within
the daemon. Frames are heap-allocated `Vec<u8>`. The Packet Pruner evicts
entries older than Staged TTL (120 s).

## Rationale

- Eliminates external dependencies for a daemon that already runs as a
  privileged pod; an external queue would require additional infrastructure.
- 120 s × (typical SYN packet size ~60 B) is negligible memory even at high
  rate; TCP SYN payloads are small.
- The Replay path only needs to write the frame back to the TAP fd; no
  serialization roundtrip is needed.

## Consequences

- Staged Packets are lost on daemon restart. The operator will need to handle
  the case where `ReplayRule` returns "not found."
- Memory consumption is unbounded between prune intervals if a large burst of
  SYNs arrives for a held IP; no backpressure mechanism exists.
- The Staging Area is not shared across daemon replicas; horizontal scaling of
  the daemon is not supported.
