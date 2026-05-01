Status: needs-triage

# Encode Capture Mode as a typed invariant

## What to build

Replace the raw `u8` `replay` field in `StateEntry` with a `CaptureMode` enum (`repr(u8)`, `PassThrough = 0`, `Hold = 1`) defined in `hold-packet-common`. Update the eBPF classifier and all userspace code (`grpc.rs`, `main.rs` Idle Monitor) to use `CaptureMode` instead of integer literals. The enum must compile under `#![no_std]` for the eBPF target and under normal conditions for the userspace target.

End-to-end: the Idle Monitor flips a Captured IP from `CaptureMode::PassThrough` to `CaptureMode::Hold` after the Idle Timeout; the eBPF classifier checks `CaptureMode::Hold` to decide whether to redirect to the TAP device. Invalid byte values are unrepresentable.

## Acceptance criteria

- [ ] `CaptureMode` `#[repr(u8)]` enum is defined in `hold-packet-common` and compiles for both eBPF (`bpfel`) and host targets.
- [ ] `StateEntry.replay` field is replaced by `StateEntry.mode: CaptureMode`; no raw `0`/`1` integer comparisons remain in `grpc.rs`, `main.rs`, or `hold-packet-ebpf/src/main.rs`.
- [ ] All existing unit tests for `calculate_state_updates` pass; tests are updated to use `CaptureMode` variants.
- [ ] `CONTEXT.md` glossary entry for `Capture Mode` is updated to reference the `CaptureMode` type.

## Blocked by

None — can start immediately.
