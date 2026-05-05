#!/usr/bin/env bash
#MISE description="Tear down the ScaleToZero control plane from vind (idempotent)"
set -euo pipefail

echo "==> Removing ScaleToZero control plane from vind..."

delete_if_exists() {
  local kind="$1" name="$2" namespace="${3:-}"
  local kubectl_args=()

  if [[ -n "$namespace" ]]; then
    kubectl_args=(-n "$namespace")
  fi

  if kubectl "${kubectl_args[@]}" get "$kind" "$name" &>/dev/null; then
    kubectl "${kubectl_args[@]}" delete "$kind" "$name"
    echo "  Deleted $kind/$name${namespace:+ (ns: $namespace)}"
  else
    echo "  $kind/$name not found — skipping"
  fi
}

# Reverse dependency order
delete_if_exists daemonset  hold-packet       hold-system
delete_if_exists deployment hold-operator     hold-system
delete_if_exists clusterrolebinding hold-operator
delete_if_exists clusterrole         hold-operator
delete_if_exists serviceaccount      hold-operator hold-system
delete_if_exists namespace           hold-system
delete_if_exists crd                 scaletozero.scale.sleepy.com

echo "==> ScaleToZero control plane removed."
