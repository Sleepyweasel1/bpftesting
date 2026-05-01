# ADR-0007: Anti-loop Guard Semantics (Option A)

**Status**: Accepted  
**Date**: 2026-05-01

## Context

The eBPF classifier currently contains an Anti-loop Guard check
(`skb.mark == 0xCAFE`) intended to prevent replayed packets from being
re-captured. In the current architecture, replayed packets are written to the
TAP device by userspace, while the TC classifier is attached only to `eth0`
ingress.

This means the replay path is already structurally separated from the capture
hook path, so a recapture loop does not occur under current hook topology.

## Decision

Adopt **Option A**:

- Remove the Anti-loop Guard mark check from the classifier.
- Treat loop prevention as a structural property of hook topology
  (TC ingress on `eth0`, replay via TAP RX).

Define correctness boundary explicitly:

- Guaranteed: **delivery-semantics correctness** (replayed traffic continues
  through kernel routing/delivery path to the intended destination).
- Not guaranteed: **per-interface policy equivalence** (behavior tied to the
  original ingress interface identity, including interface-bound firewall or
  routing policy evaluation).

## Rationale

- The current mark guard is not enforced by userspace replay today, so keeping
  it in classifier logic implies a safety mechanism that is not actually
  exercised.
- Removing dead guard logic keeps behavior and code intent aligned.
- Making the boundary explicit avoids overpromising equivalence that replay via
  TAP cannot provide.

## Consequences

- The classifier no longer depends on `skb->mark` for replay behavior.
- Existing behavior remains correct for current topology and acceptance
  criteria focused on delivery semantics.
- If capture hook topology expands beyond `eth0` ingress (for example attaching
  to TAP ingress or additional ingress points), this decision must be
  re-evaluated and explicit replay marking may need to be restored.
