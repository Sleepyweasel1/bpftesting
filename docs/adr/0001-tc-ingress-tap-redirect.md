# ADR-0001: TC Ingress Classifier + TAP Redirect for Packet Capture

**Status**: Accepted  
**Date**: 2026-05-01

> Note: Superseded in part by ADR-0007 for Anti-loop Guard semantics.
> Specifically, the rationale bullet asserting `skb->mark` use for Anti-loop
> Guard is no longer current under Option A.

## Context

The system needs to intercept packets destined for a scaled-to-zero service
and hold them until the service wakes. Several eBPF attachment points exist:
XDP (driver/generic), TC ingress/egress, and socket filters.

## Decision

Use a **TC ingress classifier** (`SchedClassifier`) attached to the upstream
interface (`eth0`). When a packet matches a Captured IP in `hold` mode, it is
redirected via `bpf_redirect()` to a **TAP device** (`tap1`) owned by the
daemon. The daemon reads frames from the TAP fd and stages them.

## Rationale

- TC has access to the full `sk_buff` including `skb->mark`, which is used for
  the Anti-loop Guard.
- XDP runs before the kernel allocates an `sk_buff`; `bpf_redirect` at XDP
  requires the destination to be an XDP-enabled device, which TAP is not.
- The TAP device delivers frames into userspace without additional kernel
  socket overhead and allows the daemon to write frames back (Replay path)
  using the same fd.

## Consequences

- The TC hook must be attached before any traffic arrives; a restart window
  exists where packets may slip through uncaptured.
- The TAP device (`tap1`) must be created before `TAP_IFINDEX` is written to the
  eBPF map; startup order matters.
- `bpf_redirect` consumes the packet (no copy); the original frame is gone if
  staging fails.
