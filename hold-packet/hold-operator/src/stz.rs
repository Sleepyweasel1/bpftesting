use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
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

#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
pub struct ScaleToZeroStatus {
    pub replicas: i32,
    checksum: String,
    last_updated: Option<Time>,
}