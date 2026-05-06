#!/usr/bin/env bash
#MISE description="Remove the ScaleToZero fixture from vind (idempotent)"
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURE_MANIFEST="$REPO_ROOT/hold-packet/deploy/vind/fixture.yaml"

echo "==> Removing fixture resources from vind..."
kubectl delete -f "$FIXTURE_MANIFEST" --ignore-not-found=true

echo "==> Fixture resources removed."
