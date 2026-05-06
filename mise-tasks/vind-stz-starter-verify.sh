#!/usr/bin/env bash
#MISE description="Run starter end-to-end ScaleToZero verification in vind"
set -euo pipefail

NS="hold-system"
DEPLOYMENT="fixture-echo"
STZ_NAME="fixture-echo"
TIMEOUT_SECONDS=120
POLL_SECONDS=3

fail() {
  local message="$1"
  echo ""
  echo "VERIFICATION_RESULT=FAIL"
  echo "FAIL_REASON=${message}"
  echo ""
  echo "--- ScaleToZero snapshot ---"
  kubectl -n "$NS" get scaletozero.scale.sleepy.com "$STZ_NAME" -o yaml || true
  echo ""
  echo "--- Deployment snapshot ---"
  kubectl -n "$NS" get deployment "$DEPLOYMENT" -o wide || true
  echo ""
  echo "--- hold-operator logs (last 120 lines) ---"
  kubectl -n "$NS" logs deployment/hold-operator --tail=120 || true
  exit 1
}

ensure_environment() {
  echo "==> Ensuring vind environment and fixture are present..."

  # Force a clean cluster lifecycle so repeated runs are deterministic.
  vcluster delete hold-packet-dev --driver docker >/dev/null 2>&1 || true
  mise run vind-up
  SKIP_DAEMONSET_READINESS=1 mise run vind-stz-up
  mise run vind-stz-fixture-up
}

recreate_scaletozero() {
  kubectl -n "$NS" delete scaletozero.scale.sleepy.com "$STZ_NAME" --ignore-not-found >/dev/null 2>&1 || true
  cat <<EOF | kubectl apply -f - >/dev/null
apiVersion: scale.sleepy.com/v0
kind: ScaleToZero
metadata:
  name: ${STZ_NAME}
  namespace: ${NS}
spec:
  target_ref:
    deployment_name: ${DEPLOYMENT}
    namespace: ${NS}
EOF
}

wait_for_expected_status() {
  local expected_intent="$1"
  local phase="$2"
  local deadline=$((SECONDS + TIMEOUT_SECONDS))

  echo "==> Verifying phase: ${phase}"
  while (( SECONDS < deadline )); do
    local generation observed intent outcome reconciled_status reconciled_reason message

    generation=$(kubectl -n "$NS" get scaletozero.scale.sleepy.com "$STZ_NAME" -o jsonpath='{.metadata.generation}' 2>/dev/null || true)
    observed=$(kubectl -n "$NS" get scaletozero.scale.sleepy.com "$STZ_NAME" -o jsonpath='{.status.observedGeneration}' 2>/dev/null || true)
    intent=$(kubectl -n "$NS" get scaletozero.scale.sleepy.com "$STZ_NAME" -o jsonpath='{.status.intent}' 2>/dev/null || true)
    outcome=$(kubectl -n "$NS" get scaletozero.scale.sleepy.com "$STZ_NAME" -o jsonpath='{.status.outcome}' 2>/dev/null || true)
    reconciled_status=$(kubectl -n "$NS" get scaletozero.scale.sleepy.com "$STZ_NAME" -o jsonpath='{.status.conditions[0].status}' 2>/dev/null || true)
    reconciled_reason=$(kubectl -n "$NS" get scaletozero.scale.sleepy.com "$STZ_NAME" -o jsonpath='{.status.conditions[0].reason}' 2>/dev/null || true)
    message=$(kubectl -n "$NS" get scaletozero.scale.sleepy.com "$STZ_NAME" -o jsonpath='{.status.message}' 2>/dev/null || true)

    if [[ -n "$generation" \
      && "$generation" == "$observed" \
      && "$intent" == "$expected_intent" ]]; then
      if [[ "$outcome" == "Succeeded" || "$outcome" == "NoOp" ]]; then
        [[ "$reconciled_status" == "True" ]] || fail "phase ${phase} expected Reconciled=True for outcome ${outcome}"
        [[ "$reconciled_reason" == "$outcome" ]] || fail "phase ${phase} expected condition reason=${outcome}, got ${reconciled_reason}"
        echo "CHECK phase=${phase} status=PASS generation=${generation} observed=${observed} intent=${intent} outcome=${outcome} reconciled_reason=${reconciled_reason}"
        return 0
      fi

      if [[ "$outcome" == "RecoverableFailure" ]]; then
        [[ "$reconciled_status" == "False" ]] || fail "phase ${phase} expected Reconciled=False for RecoverableFailure"
        [[ "$reconciled_reason" == "RecoverableFailure" ]] || fail "phase ${phase} expected condition reason=RecoverableFailure, got ${reconciled_reason}"
        if [[ "$message" == *"hold-packet agent"* || "$message" == *"agent"* ]]; then
          echo "CHECK phase=${phase} status=PASS generation=${generation} observed=${observed} intent=${intent} outcome=${outcome} message='${message}'"
          return 0
        fi
      fi
    fi

    sleep "$POLL_SECONDS"
  done

  fail "timed out waiting for ${phase}: expected intent=${expected_intent} with a valid integrated-path outcome"
}

wait_for_replicas() {
  local expected_replicas="$1"
  local deadline=$((SECONDS + TIMEOUT_SECONDS))

  while (( SECONDS < deadline )); do
    local replicas
    replicas=$(kubectl -n "$NS" get deployment "$DEPLOYMENT" -o jsonpath='{.spec.replicas}' 2>/dev/null || true)
    if [[ "$replicas" == "$expected_replicas" ]]; then
      return 0
    fi
    sleep "$POLL_SECONDS"
  done

  fail "deployment ${DEPLOYMENT} did not reach expected spec.replicas=${expected_replicas}"
}

main() {
  ensure_environment

  echo "==> Phase 1: active deployment should map to RemoveCapture"
  kubectl -n "$NS" scale deployment "$DEPLOYMENT" --replicas=1 >/dev/null
  kubectl -n "$NS" wait deployment/"$DEPLOYMENT" --for=condition=Available --timeout=120s >/dev/null || fail "deployment ${DEPLOYMENT} did not become Available at replicas=1"
  recreate_scaletozero
  wait_for_expected_status "RemoveCapture" "remove-capture"

  echo "==> Phase 2: scaled-to-zero deployment should map to HoldCapture"
  kubectl -n "$NS" scale deployment "$DEPLOYMENT" --replicas=0 >/dev/null
  wait_for_replicas "0"
  recreate_scaletozero
  wait_for_expected_status "HoldCapture" "hold-capture"

  echo "==> Phase 3: scale back up and verify RemoveCapture again"
  kubectl -n "$NS" scale deployment "$DEPLOYMENT" --replicas=1 >/dev/null
  kubectl -n "$NS" wait deployment/"$DEPLOYMENT" --for=condition=Available --timeout=120s >/dev/null || fail "deployment ${DEPLOYMENT} did not recover to Available"
  recreate_scaletozero
  wait_for_expected_status "RemoveCapture" "remove-capture-after-recover"

  echo ""
  echo "VERIFICATION_RESULT=PASS"
}

main "$@"
