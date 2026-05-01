Status: needs-triage

# Decide and enforce Anti-loop Guard semantics

## What to build

The eBPF classifier contains an `is_replayed(skb.mark == 0xCAFE)` check, but `send_packet()` in `replay.rs` currently writes raw frame bytes without setting the mark. The TC hook is on `eth0` ingress only, so no structural recapture loop exists through the TAP device today — but the intent of the guard is ambiguous.

A human decision is required: **Option A** — the guard is dead code; remove it and add a comment explaining why recapture is structurally impossible. **Option B** — the guard is intentional forward-proofing; enforce it by setting `mark = 0xCAFE` via `bpf_skb_store_bytes` before redirect or by writing the mark into the TAP frame metadata.

Once the decision is made, implement the chosen option, record it as an ADR, and verify with an integration test.

## Acceptance criteria

- [ ] Human decision recorded: Option A (remove guard) or Option B (enforce guard).
- [ ] An ADR (`docs/adr/0007-anti-loop-guard.md`) documents the decision and rationale.
- [ ] Code matches the decision: guard removed + explanatory comment, OR mark is set on every replayed frame.
- [ ] An integration test asserts the chosen invariant: either that replayed packets pass the classifier without being re-redirected, or (for Option A) that the classifier attaches and passes all traffic correctly without the mark check.

## Blocked by

None — can start immediately. Requires human decision before implementation.
