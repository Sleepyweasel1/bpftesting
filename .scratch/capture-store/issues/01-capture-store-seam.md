Status: needs-triage

# Unify Captured IP state behind a Capture Store seam

## What to build

Extract the dual-map IPv4/IPv6 branching into a single `CaptureStore` module inside `hold-packet`. All callers (`CapturelistServer`, `spawn_idle_monitor`) receive one handle rather than two typed `Arc<RwLock<BpfHashMap>>` handles. The module exposes a map-agnostic interface (`insert(IpAddr, StateEntry)`, `remove(IpAddr)`, `iter() → impl Iterator<Item=(IpAddr, StateEntry)>`) and hides the `STATEV4`/`STATEV6` split internally.

End-to-end: a `gRPC AddRule` call with an IPv4 or IPv6 address flows through `CaptureStore::insert`, hits the correct eBPF map, and a subsequent `ListRules` returns the IP — all without callers knowing which map was used.

## Acceptance criteria

- [ ] `CaptureStore` struct encapsulates both eBPF map handles; no direct map handle fields remain on `CapturelistServer` or `spawn_idle_monitor`.
- [ ] All four gRPC handlers (`AddRule`, `RemoveRule`, `ListRules`, `ReplayRule`) compile and pass existing integration tests after the refactor.
- [ ] `CaptureStore` has unit tests covering insert/remove/iter for both IPv4 and IPv6 addresses, exercised without a live eBPF environment.
- [ ] The `CaptureStore` seam is documented with a single coherent interface comment; `CONTEXT.md` is updated if any new term is introduced.

## Blocked by

None — can start immediately.
