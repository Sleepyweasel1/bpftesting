# ADR-0003: Per-Destination-IP Granularity for Capture State

**Status**: Accepted  
**Date**: 2026-05-01

## Context

The unit of Scale-to-Zero in Kubernetes is a Deployment/Service, which
typically maps to a single cluster IP (or a small set). The hold system must
decide the granularity at which Capture Mode is stored: per destination IP,
per 5-tuple (src IP + dst IP + ports + protocol), or per service.

## Decision

Track state at **per-destination-IP** granularity. The eBPF map key is the
IPv4 `u32` or IPv6 `u128` of the packet's destination address only.

## Rationale

- A Kubernetes Service ClusterIP is a single IP; all pods behind it share that
  IP as the destination in ingress traffic.
- Per-5-tuple tracking would require a larger map and more complex map-key
  construction in the eBPF classifier without adding value for the Scale-to-Zero
  use case.
- The operator knows the ClusterIP from the Kubernetes API and passes it via
  `AddRule`; no packet inspection beyond the destination IP is needed.

## Consequences

- All TCP/UDP ports on a Captured IP are captured or passed through together;
  there is no per-port granularity.
- If a service has multiple ClusterIPs (dual-stack) both must be registered
  separately via `AddRule`.
- `TargetRef` in the ScaleToZero CRD references a Deployment name; the
  operator must resolve the Deployment's Service ClusterIP(s) before calling
  `AddRule`. This resolution logic is not yet implemented.
