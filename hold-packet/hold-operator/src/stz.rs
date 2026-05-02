use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Serialize, Deserialize};


/// Specification of desired alerting rule definitions for Prometheus.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[kube(group = "scale.sleepy.com", version = "v0", kind = "ScaleToZero", plural = "scaletozero")]
#[kube(namespaced)]
#[kube(status = "ScaleToZeroStatus")]
pub struct ScaleToZeroSpec {
    // an object that defines the reference objects to target (Deployment and related service)
    pub target_ref: TargetRef,
}
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
pub struct TargetRef {
    pub deployment_name: String,
    pub namespace: String,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, JsonSchema)]
pub enum ReconcileIntent {
    HoldCapture,
    RemoveCapture,
    Replay,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, JsonSchema)]
pub enum ReconcileOutcome {
    NoOp,
    Succeeded,
    RecoverableFailure,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScaleToZeroStatus {
    pub observed_generation: i64,
    pub intent: ReconcileIntent,
    pub outcome: ReconcileOutcome,
    pub conditions: Vec<Condition>,
    pub last_reconciled_at: Option<Time>,
    pub message: Option<String>,
}