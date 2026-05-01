# ADR-0005: gRPC as the Operator–Daemon Control Plane

**Status**: Accepted  
**Date**: 2026-05-01

## Context

The Reconciler in hold-operator needs to instruct the hold-packet daemon to
add/remove Captured IPs and trigger Replay. Communication options: gRPC, REST
HTTP, Unix socket with a bespoke protocol, or direct in-process calls (if
merged into one binary).

## Decision

Expose a **gRPC service** (`CapturelistService`) from the hold-packet daemon,
defined in `holdpacket.proto`. The hold-operator will call it as a gRPC client.
The two components remain separate processes/containers.

## Rationale

- Protobuf provides a typed, versioned interface that both sides can evolve
  independently.
- gRPC is idiomatic for Kubernetes control-plane communication (matches
  Kubernetes API server patterns).
- Keeping hold-operator and hold-packet as separate binaries allows independent
  deployment, scaling, and failure domains.

## Consequences

- The hold-operator must contain a generated gRPC client stub (not yet
  implemented as of 2026-05-01).
- Network policy in the cluster must permit operator → daemon communication on
  port 50051.
- The gRPC interface is the sole public seam between the operator and daemon;
  all integration tests must go through it or a mock of it.
