use std::{sync::Arc, time::Duration};

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
use tokio::time::sleep;
use tonic::{Code, transport::Endpoint};

use hold_operator::stz::{
	ReconcileIntent,
	ReconcileOutcome,
	ScaleToZero,
	ScaleToZeroStatus,
};

use crate::holdpacket::{
	AddRuleRequest,
	RemoveRuleRequest,
	capturelist_service_client::CapturelistServiceClient,
};

pub mod holdpacket {
	tonic::include_proto!("holdpacket");
}

const AGENT_RPC_TIMEOUT: Duration = Duration::from_secs(2);
const RECONCILE_REQUEUE_DELAY: Duration = Duration::from_secs(10);
const AGENT_RETRY_BACKOFFS: [Duration; 2] = [Duration::from_millis(200), Duration::from_secs(1)];

#[derive(Clone)]
struct OperatorContext {
	client: Client,
	hold_packet_grpc_addr: String,
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
		client,
		hold_packet_grpc_addr,
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

enum AgentCallError {
	Transient(String),
	Permanent(String),
}

async fn assess_reconcile(stz: &ScaleToZero, ctx: &OperatorContext) -> ReconcileAssessment {
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

	let deployment_api: Api<Deployment> = Api::namespaced(ctx.client.clone(), &target_ref.namespace);
	let deployment = match deployment_api.get_opt(&target_ref.deployment_name).await {
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
		Err(error) => {
			return ReconcileAssessment {
				intent: ReconcileIntent::RemoveCapture,
				outcome: ReconcileOutcome::RecoverableFailure,
				message: Some(format!("failed to read target deployment: {error}")),
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

	let service_ip = match resolve_service_ip(ctx, &target_ref.namespace, &target_ref.deployment_name).await {
		Ok(service_ip) => service_ip,
		Err(message) => {
			return ReconcileAssessment {
				intent,
				outcome: ReconcileOutcome::RecoverableFailure,
				message: Some(message),
				action: Action::requeue(RECONCILE_REQUEUE_DELAY),
			};
		}
	};

	match execute_agent_intent(intent, &service_ip, &ctx.hold_packet_grpc_addr).await {
		Ok(()) => ReconcileAssessment {
			intent,
			outcome: ReconcileOutcome::Succeeded,
			message: Some(format!(
				"agent call succeeded: intent={intent:?} target_ip={service_ip}"
			)),
			action: Action::await_change(),
		},
		Err(AgentCallError::Transient(message) | AgentCallError::Permanent(message)) => ReconcileAssessment {
			intent,
			outcome: ReconcileOutcome::RecoverableFailure,
			message: Some(message),
			action: Action::requeue(RECONCILE_REQUEUE_DELAY),
		},
	}
}

async fn resolve_service_ip(
	ctx: &OperatorContext,
	namespace: &str,
	service_name: &str,
) -> Result<String, String> {
	let service_api: Api<Service> = Api::namespaced(ctx.client.clone(), namespace);
	let service = service_api
		.get_opt(service_name)
		.await
		.map_err(|error| format!("failed to read target service: {error}"))?
		.ok_or_else(|| format!("target service {namespace}/{service_name} not found"))?;

	service
		.spec
		.and_then(|spec| spec.cluster_ip)
		.filter(|cluster_ip| cluster_ip != "None")
		.ok_or_else(|| format!("target service {namespace}/{service_name} has no routable clusterIP"))
}

async fn execute_agent_intent(
	intent: ReconcileIntent,
	target_ip: &str,
	grpc_addr: &str,
) -> Result<(), AgentCallError> {
	let mut attempt = 0;
	loop {
		match try_execute_agent_intent(intent, target_ip, grpc_addr).await {
			Ok(()) => return Ok(()),
			Err(AgentCallError::Permanent(message)) => return Err(AgentCallError::Permanent(message)),
			Err(AgentCallError::Transient(message)) => {
				if attempt >= AGENT_RETRY_BACKOFFS.len() {
					return Err(AgentCallError::Transient(message));
				}

				sleep(AGENT_RETRY_BACKOFFS[attempt]).await;
				attempt += 1;
			}
		}
	}
}

async fn try_execute_agent_intent(
	intent: ReconcileIntent,
	target_ip: &str,
	grpc_addr: &str,
) -> Result<(), AgentCallError> {
	let endpoint = Endpoint::from_shared(grpc_addr.to_owned())
		.map_err(|error| AgentCallError::Permanent(format!("invalid hold-packet gRPC endpoint: {error}")))?
		.connect_timeout(AGENT_RPC_TIMEOUT)
		.timeout(AGENT_RPC_TIMEOUT);
	let channel = endpoint
		.connect()
		.await
		.map_err(|error| AgentCallError::Transient(format!("failed to connect to hold-packet agent: {error}")))?;
	let mut client = CapturelistServiceClient::new(channel);

	let response = match intent {
		ReconcileIntent::HoldCapture => client.add_rule(AddRuleRequest {
			ip: target_ip.to_owned(),
		}).await,
		ReconcileIntent::RemoveCapture => client.remove_rule(RemoveRuleRequest {
			ip: target_ip.to_owned(),
		}).await,
		ReconcileIntent::Replay => {
			return Err(AgentCallError::Permanent(
				"Replay intent is not yet wired in this slice".to_owned(),
			));
		}
	};

	let response = response.map_err(classify_tonic_status)?;
	let body = response.into_inner();
	if body.success {
		return Ok(());
	}

	Err(AgentCallError::Transient(if body.error.is_empty() {
		format!("hold-packet agent returned unsuccessful response for intent {intent:?}")
	} else {
		format!("hold-packet agent rejected request: {}", body.error)
	}))
}

fn classify_tonic_status(status: tonic::Status) -> AgentCallError {
	match status.code() {
		Code::InvalidArgument | Code::FailedPrecondition | Code::Unimplemented => {
			AgentCallError::Permanent(format!("hold-packet agent call failed permanently: {status}"))
		}
		Code::DeadlineExceeded => {
			AgentCallError::Transient("hold-packet agent call timed out".to_owned())
		}
		_ => AgentCallError::Transient(format!("hold-packet agent call failed transiently: {status}")),
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
