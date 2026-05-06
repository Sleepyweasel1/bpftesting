#!/usr/bin/env bash
#MISE description="Build and deploy the ScaleToZero control plane (hold-operator + hold-packet DaemonSet) into vind"
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY_DIR="$REPO_ROOT/hold-packet/deploy/vind"
OPERATOR_DIR="$REPO_ROOT/hold-packet"
IFACE="${HOLD_PACKET_IFACE:-eth0}"
VCLUSTER_NODE_CONTAINER="vcluster.cp.hold-packet-dev"
SKIP_DAEMONSET_READINESS="${SKIP_DAEMONSET_READINESS:-0}"

load_image_into_vind() {
  local image="$1"

  docker save "$image" | docker exec -i "$VCLUSTER_NODE_CONTAINER" ctr -n k8s.io images import -
}

echo "==> Building images..."
docker build -t hold-packet:vind-local "$OPERATOR_DIR"
docker build -t hold-operator:vind-local \
  -f - "$OPERATOR_DIR" <<'DOCKERFILE'
FROM rust:1.94-slim-bookworm AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config protobuf-compiler clang lld && rm -rf /var/lib/apt/lists/*
COPY . .
RUN cargo build --release -p hold-operator
FROM gcr.io/distroless/cc-debian12
COPY --from=builder /app/target/release/hold-operator /hold-operator
ENTRYPOINT ["/hold-operator"]
DOCKERFILE

echo "==> Loading images into vind cluster..."
load_image_into_vind hold-packet:vind-local
load_image_into_vind hold-operator:vind-local

echo "==> Generating CRD from source..."
(cd "$OPERATOR_DIR" && cargo run --quiet --release -p hold-operator --bin crd-gen) \
  > "$DEPLOY_DIR/crd-scaletozero.yaml"

echo "==> Applying resources..."
kubectl apply -f "$DEPLOY_DIR/namespace.yaml"
kubectl apply -f "$DEPLOY_DIR/crd-scaletozero.yaml"
kubectl apply -f "$DEPLOY_DIR/rbac.yaml"
kubectl apply -f "$DEPLOY_DIR/hold-operator-deployment.yaml"

# Inject interface name into DaemonSet manifest on the fly
IFACE="$IFACE" kubectl apply -f <(
  sed "s/value: eth0/value: ${IFACE}/" "$DEPLOY_DIR/hold-packet-daemonset.yaml"
)

echo "==> Running smoke checks..."
smoke_fail() {
  echo ""
  echo "!!! Smoke check failed — preserving resources for debugging !!!"
  echo ""
  echo "--- Pods in hold-system ---"
  kubectl -n hold-system get pods -o wide || true
  echo ""
  echo "--- Events in hold-system ---"
  kubectl -n hold-system get events --sort-by='.lastTimestamp' || true
  echo ""
  echo "--- hold-operator Deployment ---"
  kubectl -n hold-system describe deployment hold-operator || true
  echo ""
  echo "--- hold-packet DaemonSet ---"
  kubectl -n hold-system describe daemonset hold-packet || true
  exit 1
}

echo "  Checking CRD registration..."
kubectl get crd scaletozero.scale.sleepy.com > /dev/null || smoke_fail

echo "  Waiting for hold-operator Deployment to be Available..."
kubectl -n hold-system wait deployment/hold-operator \
  --for=condition=Available --timeout=120s || smoke_fail

echo "  Waiting for hold-packet DaemonSet to be ready..."
if [[ "$SKIP_DAEMONSET_READINESS" == "1" ]]; then
  echo "  Skipping DaemonSet readiness check (SKIP_DAEMONSET_READINESS=1)"
else
  TIMEOUT=120
  ELAPSED=0
  while true; do
    DESIRED=$(kubectl -n hold-system get daemonset hold-packet -o jsonpath='{.status.desiredNumberScheduled}' 2>/dev/null || echo "0")
    READY=$(kubectl -n hold-system get daemonset hold-packet -o jsonpath='{.status.numberReady}' 2>/dev/null || echo "0")
    if [[ "$DESIRED" -gt 0 && "$DESIRED" == "$READY" ]]; then
      break
    fi
    if [[ "$ELAPSED" -ge "$TIMEOUT" ]]; then
      echo "  DaemonSet not ready: desired=$DESIRED ready=$READY"
      smoke_fail
    fi
    sleep 5
    ELAPSED=$((ELAPSED + 5))
  done
fi

echo ""
echo "==> ScaleToZero control plane is ready in vind."
echo "    hold-operator:  deployment/hold-operator  (namespace: hold-system)"
echo "    hold-packet:    daemonset/hold-packet      (namespace: hold-system, iface: ${IFACE})"
