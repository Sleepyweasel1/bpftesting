use std::{
	collections::{BTreeSet, HashMap},
	net::IpAddr,
	sync::Arc,
	time::Duration,
};

use async_trait::async_trait;
use futures::StreamExt;
use k8s_openapi::{
	api::{apps::v1::Deployment, core::v1::Service},
	apimachinery::pkg::apis::meta::v1::{Condition, Time},
	jiff::Timestamp,
};
use kube::{
	Api, Client, Resource, ResourceExt,
	api::{Patch, PatchParams},
	runtime::{
		Controller,
		controller::Action,
		watcher,
	},
};
use log::{error, info};
use rustls::crypto::ring::default_provider;
use serde_json::json;

use hold_operator::stz::{
	ReconcileIntent,
	ReconcileOutcome,
	ScaleToZero,
	ScaleToZeroStatus,
};

use capture_control::{CaptureControl, CaptureControlError, HoldPacketClient};

pub mod holdpacket {
	tonic::include_proto!("holdpacket");
}
mod capture_control;

const RECONCILE_REQUEUE_DELAY: Duration = Duration::from_secs(10);
const AGENT_RETRY_BACKOFFS: [Duration; 2] = [Duration::from_millis(200), Duration::from_secs(1)];

#[derive(Clone)]
struct OperatorContext {
	client: Client,
	state_reader: Arc<dyn KubeStateReader>,
	capture_control: Arc<dyn CaptureControl>,
}

#[async_trait]
trait KubeStateReader: Send + Sync {
	async fn get_deployment(&self, namespace: &str, name: &str) -> Result<Option<Deployment>, String>;
	async fn list_services(&self, namespace: &str) -> Result<Vec<Service>, String>;
}

struct ApiKubeStateReader {
	client: Client,
}

#[async_trait]
impl KubeStateReader for ApiKubeStateReader {
	async fn get_deployment(&self, namespace: &str, name: &str) -> Result<Option<Deployment>, String> {
		let deployment_api: Api<Deployment> = Api::namespaced(self.client.clone(), namespace);
		deployment_api
			.get_opt(name)
			.await
			.map_err(|error| format!("failed to read target deployment: {error}"))
	}

	async fn list_services(&self, namespace: &str) -> Result<Vec<Service>, String> {
		let service_api: Api<Service> = Api::namespaced(self.client.clone(), namespace);
		service_api
			.list(&Default::default())
			.await
			.map(|services| services.items)
			.map_err(|error| format!("failed to list services: {error}"))
	}
}

#[tokio::main]
async fn main() -> Result<(), kube::Error> {
	env_logger::init();
	default_provider()
		.install_default()
		.expect("failed to install rustls crypto provider");

	info!("starting hold-operator controller");

	let client = Client::try_default().await?;
	let stz_api: Api<ScaleToZero> = Api::all(client.clone());
	let hold_packet_grpc_addr = std::env::var("HOLD_PACKET_GRPC_ADDR")
		.unwrap_or_else(|_| "http://127.0.0.1:50051".to_owned());
	let ctx = Arc::new(OperatorContext {
		client: client.clone(),
		state_reader: Arc::new(ApiKubeStateReader {
			client: client.clone(),
		}),
		capture_control: Arc::new(HoldPacketClient::new(hold_packet_grpc_addr)),
	});

	Controller::new(stz_api, watcher::Config::default())
		.run(reconcile, error_policy, ctx)
		.for_each(|result| async move {
			match result {
				Ok((object_ref, action)) => {
					info!(
						"reconcile completed: namespace={:?} name={} action={:?}",
						object_ref.namespace,
						object_ref.name,
						action
					);
				}
				Err(error) => {
					error!("reconcile failed: {error:#}");
				}
			}
		})
		.await;

	Ok(())
}

async fn reconcile(stz: Arc<ScaleToZero>, ctx: Arc<OperatorContext>) -> Result<Action, kube::Error> {
	let Some(namespace) = stz.namespace() else {
		error!("reconcile skipped: ScaleToZero is unexpectedly cluster-scoped");
		return Ok(Action::requeue(RECONCILE_REQUEUE_DELAY));
	};
	let name = stz.name_any();
	let generation = stz.meta().generation.unwrap_or_default();
	let assessment = assess_reconcile(&stz, &ctx).await;

	info!(
		"reconciling ScaleToZero: namespace={} name={}",
		namespace,
		name
	);

	let desired_status = ScaleToZeroStatus {
		observed_generation: generation,
		intent: assessment.intent,
		outcome: assessment.outcome,
		conditions: vec![build_reconciled_condition(
			generation,
			assessment.outcome,
			assessment.message.as_deref().unwrap_or(""),
		)],
		last_reconciled_at: None,
		message: assessment.message.clone(),
	};

	let semantic_change = status_semantics_changed(stz.status.as_ref(), &desired_status);
	if semantic_change {
		let mut status_to_write = desired_status;
		status_to_write.last_reconciled_at = Some(now_time());

		let patch_payload = json!({ "status": status_to_write });
		let stz_api: Api<ScaleToZero> = Api::namespaced(ctx.client.clone(), &namespace);
		stz_api
			.patch_status(
				&name,
				&PatchParams::default(),
				&Patch::Merge(&patch_payload),
			)
			.await?;

		info!(
			"status updated: namespace={} name={} intent={:?} outcome={:?}",
			namespace,
			name,
			assessment.intent,
			assessment.outcome
		);
	} else {
		info!(
			"status unchanged: namespace={} name={} intent={:?} outcome={:?}",
			namespace,
			name,
			assessment.intent,
			assessment.outcome
		);
	}

	Ok(assessment.action)
}

fn error_policy(
	stz: Arc<ScaleToZero>,
	err: &kube::Error,
	_ctx: Arc<OperatorContext>,
) -> Action {
	error!(
		"error policy triggered: namespace={:?} name={} error={err}",
		stz.namespace(),
		stz.name_any()
	);

	Action::requeue(std::time::Duration::from_secs(10))
}

struct ReconcileAssessment {
	intent: ReconcileIntent,
	outcome: ReconcileOutcome,
	message: Option<String>,
	action: Action,
}

async fn assess_reconcile(stz: &ScaleToZero, ctx: &OperatorContext) -> ReconcileAssessment {
	assess_reconcile_with_readers(stz, ctx.state_reader.as_ref(), ctx.capture_control.as_ref()).await
}

async fn assess_reconcile_with_readers(
	stz: &ScaleToZero,
	state_reader: &dyn KubeStateReader,
	capture_control: &dyn CaptureControl,
) -> ReconcileAssessment {
	let generation = stz.meta().generation.unwrap_or_default();
	let current_status = stz.status.as_ref();
	let target_ref = &stz.spec.target_ref;

	if target_ref.deployment_name.trim().is_empty() {
		return ReconcileAssessment {
			intent: ReconcileIntent::RemoveCapture,
			outcome: ReconcileOutcome::RecoverableFailure,
			message: Some("target_ref.deployment_name must not be empty".to_owned()),
			action: Action::requeue(RECONCILE_REQUEUE_DELAY),
		};
	}

	if target_ref.namespace.trim().is_empty() {
		return ReconcileAssessment {
			intent: ReconcileIntent::RemoveCapture,
			outcome: ReconcileOutcome::RecoverableFailure,
			message: Some("target_ref.namespace must not be empty".to_owned()),
			action: Action::requeue(RECONCILE_REQUEUE_DELAY),
		};
	}

	let deployment = match state_reader
		.get_deployment(&target_ref.namespace, &target_ref.deployment_name)
		.await
	{
		Ok(Some(deployment)) => deployment,
		Ok(None) => {
			return ReconcileAssessment {
				intent: ReconcileIntent::RemoveCapture,
				outcome: ReconcileOutcome::RecoverableFailure,
				message: Some(format!(
					"target deployment {}/{} not found",
					target_ref.namespace,
					target_ref.deployment_name
				)),
				action: Action::requeue(RECONCILE_REQUEUE_DELAY),
			};
		}
		Err(message) => {
			return ReconcileAssessment {
				intent: ReconcileIntent::RemoveCapture,
				outcome: ReconcileOutcome::RecoverableFailure,
				message: Some(message),
				action: Action::requeue(RECONCILE_REQUEUE_DELAY),
			};
		}
	};

	let replicas = deployment
		.spec
		.as_ref()
		.and_then(|spec| spec.replicas)
		.unwrap_or(1);
	let intent = if replicas == 0 {
		ReconcileIntent::HoldCapture
	} else {
		ReconcileIntent::RemoveCapture
	};

	if current_status
		.map(|status| {
			status.observed_generation == generation
				&& status.intent == intent
				&& matches!(status.outcome, ReconcileOutcome::Succeeded | ReconcileOutcome::NoOp)
		})
		.unwrap_or(false)
	{
		return ReconcileAssessment {
			intent,
			outcome: ReconcileOutcome::NoOp,
			message: Some("intent already applied to hold-packet agent".to_owned()),
			action: Action::await_change(),
		};
	}

	let services = match state_reader.list_services(&target_ref.namespace).await {
		Ok(services) => services,
		Err(message) => {
			return ReconcileAssessment {
				intent,
				outcome: ReconcileOutcome::RecoverableFailure,
				message: Some(message),
				action: Action::requeue(RECONCILE_REQUEUE_DELAY),
			};
		}
	};
	let target_ips = match resolve_service_cluster_ips_for_deployment(
		&deployment,
		&services,
		&target_ref.namespace,
		&target_ref.deployment_name,
	) {
		Ok(ips) => ips,
		Err(message) => {
			return ReconcileAssessment {
				intent,
				outcome: ReconcileOutcome::RecoverableFailure,
				message: Some(message),
				action: Action::requeue(RECONCILE_REQUEUE_DELAY),
			};
		}
	};

	match execute_agent_intent_for_ips(intent, &target_ips, capture_control).await {
		Ok(()) => ReconcileAssessment {
			intent,
			outcome: ReconcileOutcome::Succeeded,
			message: Some(format!(
				"agent call succeeded: intent={intent:?} target_ips={}",
				target_ips.join(",")
			)),
			action: Action::await_change(),
		},
		Err(CaptureControlError::Transient(message) | CaptureControlError::Permanent(message)) => {
			ReconcileAssessment {
				intent,
				outcome: ReconcileOutcome::RecoverableFailure,
				message: Some(message),
				action: Action::requeue(RECONCILE_REQUEUE_DELAY),
			}
		}
	}
}

fn resolve_service_cluster_ips_for_deployment(
	deployment: &Deployment,
	services: &[Service],
	namespace: &str,
	deployment_name: &str,
) -> Result<Vec<String>, String> {
	let deployment_labels = deployment
		.spec
		.as_ref()
		.and_then(|spec| spec.template.metadata.as_ref())
		.and_then(|metadata| metadata.labels.clone())
		.ok_or_else(|| {
			format!(
				"target deployment {namespace}/{deployment_name} has no pod template labels"
			)
		})?;

	let matching_services: Vec<&Service> = services
		.iter()
		.filter(|service| {
			service
				.spec
				.as_ref()
				.and_then(|spec| spec.selector.as_ref())
				.filter(|selector| !selector.is_empty())
				.map(|selector| selector.iter().all(|(k, v)| deployment_labels.get(k) == Some(v)))
				.unwrap_or(false)
		})
		.collect();

	if matching_services.is_empty() {
		return Err(format!(
			"no services in namespace {namespace} match deployment {deployment_name} selector labels"
		));
	}

	let mut routable_ips = BTreeSet::new();
	for service in matching_services {
		if let Some(spec) = &service.spec {
			if let Some(cluster_ips) = &spec.cluster_ips {
				for ip in cluster_ips {
					if ip != "None" {
						routable_ips.insert(ip.clone());
					}
				}
			}

			if let Some(cluster_ip) = &spec.cluster_ip {
				if cluster_ip != "None" {
					routable_ips.insert(cluster_ip.clone());
				}
			}
		}
	}

	if routable_ips.is_empty() {
		return Err(format!(
			"matching services for deployment {namespace}/{deployment_name} have no routable clusterIP"
		));
	}

	for ip in &routable_ips {
		if ip.parse::<IpAddr>().is_err() {
			return Err(format!(
				"matching service for deployment {namespace}/{deployment_name} returned invalid clusterIP {ip:?}"
			));
		}
	}

	Ok(routable_ips.into_iter().collect())
}

async fn execute_agent_intent_for_ips(
	intent: ReconcileIntent,
	target_ips: &[String],
	capture_control: &dyn CaptureControl,
) -> Result<(), CaptureControlError> {
	for target_ip in target_ips {
		execute_agent_intent(intent, target_ip, capture_control).await?;
	}

	Ok(())
}

async fn execute_agent_intent(
	intent: ReconcileIntent,
	target_ip: &str,
	capture_control: &dyn CaptureControl,
) -> Result<(), CaptureControlError> {
	let ip: IpAddr = target_ip
		.parse()
		.map_err(|e| CaptureControlError::Permanent(format!("invalid target IP {target_ip:?}: {e}")))?
;
	let mut attempt = 0;
	loop {
		let result = match intent {
			ReconcileIntent::HoldCapture => capture_control.add_rule(ip).await,
			ReconcileIntent::RemoveCapture => capture_control.remove_rule(ip).await,
			ReconcileIntent::Replay => {
				return Err(CaptureControlError::Permanent(
					"Replay intent is not yet wired in this slice".to_owned(),
				));
			}
		};
		match result {
			Ok(()) => return Ok(()),
			Err(CaptureControlError::Permanent(message)) => {
				return Err(CaptureControlError::Permanent(message));
			}
			Err(CaptureControlError::Transient(message)) => {
				if attempt >= AGENT_RETRY_BACKOFFS.len() {
					return Err(CaptureControlError::Transient(message));
				}
				tokio::time::sleep(AGENT_RETRY_BACKOFFS[attempt]).await;
				attempt += 1;
			}
		}
	}
}

fn build_reconciled_condition(
	observed_generation: i64,
	outcome: ReconcileOutcome,
	message: &str,
) -> Condition {
	let (status, reason) = match outcome {
		ReconcileOutcome::NoOp => ("True", "NoOp"),
		ReconcileOutcome::Succeeded => ("True", "Succeeded"),
		ReconcileOutcome::RecoverableFailure => ("False", "RecoverableFailure"),
	};

	Condition {
		type_: "Reconciled".to_owned(),
		status: status.to_owned(),
		observed_generation: Some(observed_generation),
		last_transition_time: now_time(),
		reason: reason.to_owned(),
		message: message.to_owned(),
	}
}

fn now_time() -> Time {
	Time(Timestamp::now())
}

fn status_semantics_changed(
	current: Option<&ScaleToZeroStatus>,
	desired: &ScaleToZeroStatus,
) -> bool {
	let Some(current) = current else {
		return true;
	};

	if current.observed_generation != desired.observed_generation
		|| current.intent != desired.intent
		|| current.outcome != desired.outcome
		|| current.message != desired.message
	{
		return true;
	}

	let current_reconciled = reconciled_condition_signature(&current.conditions);
	let desired_reconciled = reconciled_condition_signature(&desired.conditions);
	current_reconciled != desired_reconciled
}

fn reconciled_condition_signature(conditions: &[Condition]) -> Option<(&str, &str, &str)> {
	conditions
		.iter()
		.find(|condition| condition.type_ == "Reconciled")
		.map(|condition| {
			(
				condition.status.as_str(),
				condition.reason.as_str(),
				condition.message.as_str(),
			)
		})
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::capture_control::FakeCaptureControl;
	use hold_operator::stz::{ScaleToZeroSpec, TargetRef};
	use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
	use serde_json::json;

	struct FakeKubeStateReader {
		deployment: Option<Deployment>,
		services: Vec<Service>,
		deployment_error: Option<String>,
		services_error: Option<String>,
	}

	#[async_trait]
	impl KubeStateReader for FakeKubeStateReader {
		async fn get_deployment(&self, _namespace: &str, _name: &str) -> Result<Option<Deployment>, String> {
			if let Some(error) = &self.deployment_error {
				return Err(error.clone());
			}
			Ok(self.deployment.clone())
		}

		async fn list_services(&self, _namespace: &str) -> Result<Vec<Service>, String> {
			if let Some(error) = &self.services_error {
				return Err(error.clone());
			}
			Ok(self.services.clone())
		}
	}

	fn build_stz(namespace: &str, deployment_name: &str) -> ScaleToZero {
		let mut stz = ScaleToZero::new(
			"demo",
			ScaleToZeroSpec {
				target_ref: TargetRef {
					deployment_name: deployment_name.to_owned(),
					namespace: namespace.to_owned(),
				},
			},
		);
		stz.metadata = ObjectMeta {
			name: Some("demo".to_owned()),
			namespace: Some(namespace.to_owned()),
			generation: Some(1),
			..ObjectMeta::default()
		};
		stz
	}

	fn deployment_with_labels(name: &str, replicas: i32, labels: &[(&str, &str)]) -> Deployment {
		serde_json::from_value(json!({
			"apiVersion": "apps/v1",
			"kind": "Deployment",
			"metadata": { "name": name },
			"spec": {
				"replicas": replicas,
				"selector": {
					"matchLabels": labels.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect::<HashMap<_, _>>()
				},
				"template": {
					"metadata": {
						"labels": labels.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect::<HashMap<_, _>>()
					},
					"spec": {
						"containers": [{ "name": "app", "image": "nginx" }]
					}
				}
			}
		}))
		.expect("deployment json should deserialize")
	}

	fn service_with_selector(name: &str, selector: &[(&str, &str)], ips: &[&str]) -> Service {
		serde_json::from_value(json!({
			"apiVersion": "v1",
			"kind": "Service",
			"metadata": { "name": name },
			"spec": {
				"selector": selector.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect::<HashMap<_, _>>(),
				"clusterIP": ips.first().copied().unwrap_or("None"),
				"clusterIPs": ips,
				"ports": [{"port": 80, "targetPort": 80}],
				"type": "ClusterIP"
			}
		}))
		.expect("service json should deserialize")
	}

	#[test]
	fn resolves_selector_matched_service_cluster_ips() {
		let deployment = deployment_with_labels("api", 0, &[("app", "api")]);
		let services = vec![
			service_with_selector("api-v4", &[("app", "api")], &["10.96.0.1"]),
			service_with_selector(
				"api-dual",
				&[("app", "api")],
				&["10.96.0.2", "fd00::100"],
			),
			service_with_selector("other", &[("app", "other")], &["10.96.0.99"]),
		];

		let result = resolve_service_cluster_ips_for_deployment(&deployment, &services, "default", "api")
			.expect("resolution should succeed");

		assert_eq!(result, vec!["10.96.0.1", "10.96.0.2", "fd00::100"]);
	}

	#[test]
	fn errors_when_no_selector_match_exists() {
		let deployment = deployment_with_labels("api", 0, &[("app", "api")]);
		let services = vec![service_with_selector("other", &[("app", "other")], &["10.96.0.99"])];

		let result = resolve_service_cluster_ips_for_deployment(&deployment, &services, "default", "api");
		assert!(result.is_err());
	}

	#[tokio::test]
	async fn reconcile_scale_down_adds_all_resolved_ips() {
		let stz = build_stz("default", "api");
		let deployment = deployment_with_labels("api", 0, &[("app", "api")]);
		let services = vec![
			service_with_selector("api-v4", &[("app", "api")], &["10.96.0.1"]),
			service_with_selector(
				"api-dual",
				&[("app", "api")],
				&["10.96.0.2", "fd00::100"],
			),
		];
		let reader = FakeKubeStateReader {
			deployment: Some(deployment),
			services,
			deployment_error: None,
			services_error: None,
		};
		let capture = FakeCaptureControl::new();

		let assessment = assess_reconcile_with_readers(&stz, &reader, &capture).await;
		assert_eq!(assessment.outcome, ReconcileOutcome::Succeeded);

		let add_calls = capture.add_calls.lock().unwrap().clone();
		assert_eq!(add_calls.len(), 3);
		assert!(add_calls.iter().any(|ip| ip.to_string() == "10.96.0.1"));
		assert!(add_calls.iter().any(|ip| ip.to_string() == "10.96.0.2"));
		assert!(add_calls.iter().any(|ip| ip.to_string() == "fd00::100"));
	}

	#[tokio::test]
	async fn reconcile_scale_up_removes_all_resolved_ips() {
		let stz = build_stz("default", "api");
		let deployment = deployment_with_labels("api", 2, &[("app", "api")]);
		let services = vec![service_with_selector("api-v4", &[("app", "api")], &["10.96.0.1", "fd00::101"])];
		let reader = FakeKubeStateReader {
			deployment: Some(deployment),
			services,
			deployment_error: None,
			services_error: None,
		};
		let capture = FakeCaptureControl::new();

		let assessment = assess_reconcile_with_readers(&stz, &reader, &capture).await;
		assert_eq!(assessment.outcome, ReconcileOutcome::Succeeded);

		let remove_calls = capture.remove_calls.lock().unwrap().clone();
		assert_eq!(remove_calls.len(), 2);
		assert!(remove_calls.iter().any(|ip| ip.to_string() == "10.96.0.1"));
		assert!(remove_calls.iter().any(|ip| ip.to_string() == "fd00::101"));
	}
}
