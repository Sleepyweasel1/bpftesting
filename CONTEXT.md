# Domain Glossary — hold-packet

This file is the canonical vocabulary for the hold-packet domain. All agent
output (issue titles, refactor proposals, test names, ADR text) must use these
terms exactly.

---

## Core Concepts

**Scale-to-Zero**
The operator-driven lifecycle event where a Deployment is scaled down to 0
replicas. The hold-packet system exists to handle traffic that arrives while
the Deployment is in this state.

**Captured IP**
An IP address registered in the eBPF state maps (`STATEV4` / `STATEV6`). All
packets whose destination matches a Captured IP are subject to the hold
decision.

**Capture Mode**
The current disposition assigned to a Captured IP, stored as `StateEntry.mode` using the `CaptureMode`
enum defined in `hold-packet-common`. Variants:
- `CaptureMode::PassThrough` (discriminant 0): service is live; packets flow normally.
- `CaptureMode::Hold` (discriminant 1): service is scaled-to-zero; packets are redirected to the
  TAP device.
  TAP device.

**StateEntry**
The shared kernel↔userspace record for a single Captured IP, defined in `hold-packet-common`.
Carries `last_seen_ns`, `packet_count`, and the current `Capture Mode` (as a `CaptureMode` enum).

**Idle Timeout**
The configurable period of inactivity (default 300 s) after which a Captured IP
transitions from `pass-through` to `hold`. Evaluated by the Idle Monitor.

**Idle Monitor**
The background task (30 s polling loop) that reads the eBPF state maps and
flips Capture Mode based on elapsed time since `last_seen_ns`.

**Staged Packet**
A raw L2 frame that was redirected to the TAP device while the destination IP
was in `hold` mode, stored in memory with a unique numeric ID and a staging
timestamp.

**Staging Area**
The in-process `HashMap<u64, StagedPacket>` that accumulates Staged Packets
awaiting an operator replay or TTL eviction.

**Staged TTL**
The maximum age of a Staged Packet before it is pruned (120 s). Chosen to
cover the Linux TCP SYN retransmit window.

**Replay**
The act of writing a Staged Packet back to the TAP device so the kernel
delivers it to the woken service. Triggered by the operator via `ReplayRule`.

**Packet Pruner**
The background task (30 s interval) that evicts Staged Packets whose
`staged_at` age exceeds Staged TTL.

**TAP Device**
The virtual L2 interface (`tap1`) owned by the daemon. Receives redirected
packets from the eBPF classifier; writes to it during Replay.

**Anti-loop Guard**
Under Option A, recapture prevention is a structural topology property, not a
packet mark check: TC capture runs on `eth0` ingress while replay is injected
via TAP RX. Correctness is defined as delivery semantics, not per-interface
policy equivalence. See ADR-0007 (and ADR-0001 partial supersession note).

**ScaleToZero CRD**
The Kubernetes custom resource (`scale.sleepy.com/v0/ScaleToZero`) that the
hold-operator watches. Carries a `target_ref` (deployment name + namespace).

**Reconciler**
The controller loop in hold-operator that receives ScaleToZero events and
should drive the hold-packet gRPC control plane in response.

**Control Plane (gRPC)**
The `CapturelistService` gRPC interface exposed by the daemon on port 50051.
The Reconciler is the intended sole client; exposes `AddRule`, `RemoveRule`,
`ListRules`, and `ReplayRule`.

**CapturelistServer**
The tonic service struct that implements `CapturelistService`, bridging the
gRPC surface to the eBPF state maps and the Staging Area.

**Capture Store**
The userspace seam that encapsulates dual eBPF state maps (`STATEV4` / `STATEV6`)
behind one map-agnostic interface keyed by `IpAddr`. It is the boundary that
keeps address-family branching and map-type details out of gRPC handlers and
background workers.
