#!/usr/bin/env bash
#MISE description="Tear down the hold-packet-dev vcluster (idempotent)"
set -euo pipefail

CLUSTER="hold-packet-dev"

if vcluster list --driver docker --output json | jq -r '.[].Name' | grep -q "^${CLUSTER}$"; then
  echo "Deleting vcluster '$CLUSTER'..."
  vcluster delete "$CLUSTER" --driver docker
  echo "Cluster '$CLUSTER' deleted."
else
  echo "Cluster '$CLUSTER' not found — nothing to do."
fi
