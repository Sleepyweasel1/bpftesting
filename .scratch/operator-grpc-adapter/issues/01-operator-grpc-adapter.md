Status: needs-triage

# Add hold-operator gRPC adapter for CapturelistService

## What to build

Add a generated tonic gRPC client to `hold-operator` and wrap it in a concrete `HoldPacketClient` adapter struct that exposes typed methods: `add_rule(IpAddr)`, `remove_rule(IpAddr)`, `list_rules() -> Vec<IpAddr>`, `replay_rule(id: u64)`. The adapter is constructed from a daemon endpoint URL and stored in `OperatorContext`. Introduce a trait `CaptureControl` backed by the adapter so tests can substitute a fake.

End-to-end: `hold-operator` binary starts, connects to `hold-packet` gRPC endpoint, calls `add_rule("10.96.0.1")`, and receives a success response — verifiable via the existing gRPC server run in an integration test.

## Acceptance criteria

- [ ] `hold-operator/Cargo.toml` references the `holdpacket.proto` build step and tonic client code is generated at compile time.
- [ ] `HoldPacketClient` wraps the generated stub and compiles against the current proto definition.
- [ ] `CaptureControl` trait is defined; `HoldPacketClient` and a `FakeCaptureControl` test double both implement it.
- [ ] A unit test using `FakeCaptureControl` verifies that the adapter correctly translates `IpAddr` arguments to proto string form.
- [ ] `OperatorContext` carries an `Arc<dyn CaptureControl>` field.

## Blocked by

None — can start immediately.
