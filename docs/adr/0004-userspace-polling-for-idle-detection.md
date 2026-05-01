# ADR-0004: Userspace Polling for Idle Detection

**Status**: Accepted  
**Date**: 2026-05-01

## Context

The system must detect when no traffic has been seen for a Captured IP for
longer than the Idle Timeout and flip Capture Mode to `hold`. Detection options:
- Userspace polling loop reading `last_seen_ns` from the eBPF maps.
- eBPF perf/ring-buffer event emitted when a packet is the first to exceed the
  idle window.
- A kernel BPF timer (available since Linux 5.15) firing inside the eBPF
  program.

## Decision

Use a **userspace 30 s polling loop** (the Idle Monitor) that iterates all
map entries, computes elapsed time, and writes back updated `StateEntry` values
for any entries whose Capture Mode should change.

## Rationale

- Simplest correct implementation: no BPF timer complexity, no ring-buffer
  consumer goroutine, no ordering guarantees needed.
- Idle detection does not need to be precise to the second; a 30 s polling
  interval with a 300 s default timeout gives ≤10 % jitter, which is acceptable
  for a scale-to-zero trigger.
- The pure state-transition function (`calculate_state_updates`) is unit-tested
  independently of the map I/O.

## Consequences

- Capture Mode flip latency is up to 30 s beyond the Idle Timeout. This is
  intentional and acceptable.
- The polling loop holds a read lock on the map handle, then a write lock for
  the update phase. Concurrent gRPC `AddRule`/`RemoveRule` calls will contend
  during the write phase.
- Linux < 5.15 doesn't support BPF timers; the polling approach works on any
  kernel that supports TC eBPF.
