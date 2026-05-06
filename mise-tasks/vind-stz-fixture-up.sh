#!/usr/bin/env bash
#MISE description="Apply a stable ScaleToZero fixture into vind and run smoke checks"
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURE_MANIFEST="$REPO_ROOT/hold-packet/deploy/vind/fixture.yaml"

smoke_fail() {
  echo ""
  echo "!!! Fixture smoke check failed !!!"
  echo ""
  echo "--- fixture resources (hold-system) ---"
  kubectl -n hold-system get deployment/fixture-echo service/fixture-echo scaletozero.scale.sleepy.com/fixture-echo || true
  echo ""
  echo "--- deployment describe ---"
  kubectl -n hold-system describe deployment fixture-echo || true
  echo ""
  echo "--- pod list ---"
  kubectl -n hold-system get pods -l app=fixture-echo -o wide || true
  echo ""
  echo "--- events ---"
  kubectl -n hold-system get events --sort-by='.lastTimestamp' || true
  exit 1
}

echo "==> Applying fixture manifest..."
kubectl apply -f "$FIXTURE_MANIFEST"

echo "==> Running fixture smoke checks..."
kubectl get crd scaletozero.scale.sleepy.com > /dev/null || smoke_fail
kubectl -n hold-system wait deployment/fixture-echo --for=condition=Available --timeout=120s || smoke_fail
kubectl -n hold-system get service fixture-echo > /dev/null || smoke_fail
kubectl -n hold-system get scaletozero.scale.sleepy.com fixture-echo > /dev/null || smoke_fail

echo "==> Fixture is ready in vind."
