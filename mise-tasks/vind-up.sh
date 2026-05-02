#!/usr/bin/env bash
#MISE description="Create the hold-packet-dev vcluster (Docker driver) and wait for node Ready"
set -euo pipefail

CLUSTER="hold-packet-dev"

echo "Creating vcluster '$CLUSTER' with Docker driver..."
vcluster create "$CLUSTER" --driver docker

echo "Waiting for node to reach Ready state..."
kubectl wait node --all --for=condition=Ready --timeout=120s

echo "Cluster '$CLUSTER' is ready."
