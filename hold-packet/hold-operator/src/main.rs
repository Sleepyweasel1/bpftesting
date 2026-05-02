use std::{sync::Arc, time::Duration};

use futures::StreamExt;
use k8s_openapi::{
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
use serde_json::json;

use hold_operator::stz::{
	ReconcileIntent,
	ReconcileOutcome,
	ScaleToZero,
	ScaleToZeroStatus,
};

#[derive(Clone)]
struct OperatorContext {
	client: Client,
}

#[tokio::main]
async fn main() -> Result<(), kube::Error> {
	env_logger::init();

	info!("starting hold-operator controller");

	let client = Client::try_default().await?;
	let stz_api: Api<ScaleToZero> = Api::all(client.clone());
	let ctx = Arc::new(OperatorContext {
		client,
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
		return Ok(Action::requeue(Duration::from_secs(10)));
	};
	let name = stz.name_any();
	let generation = stz.meta().generation.unwrap_or_default();
	let assessment = assess_reconcile(&stz);

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

fn assess_reconcile(stz: &ScaleToZero) -> ReconcileAssessment {
	let generation = stz.meta().generation.unwrap_or_default();
	let current_status = stz.status.as_ref();

	if stz.spec.target_ref.deployment_name.trim().is_empty() {
		return ReconcileAssessment {
			intent: ReconcileIntent::RemoveCapture,
			outcome: ReconcileOutcome::RecoverableFailure,
			message: Some("target_ref.deployment_name must not be empty".to_owned()),
			action: Action::requeue(Duration::from_secs(10)),
		};
	}

	if stz.spec.target_ref.namespace.trim().is_empty() {
		return ReconcileAssessment {
			intent: ReconcileIntent::RemoveCapture,
			outcome: ReconcileOutcome::RecoverableFailure,
			message: Some("target_ref.namespace must not be empty".to_owned()),
			action: Action::requeue(Duration::from_secs(10)),
		};
	}

	// This starter loop has not yet integrated deployment/gRPC side-effects.
	let intent = ReconcileIntent::HoldCapture;
	let outcome = if current_status
		.map(|status| status.observed_generation == generation && status.intent == intent)
		.unwrap_or(false)
	{
		ReconcileOutcome::NoOp
	} else {
		ReconcileOutcome::Succeeded
	};

	let message = match outcome {
		ReconcileOutcome::NoOp => Some("intent already reflected in status".to_owned()),
		ReconcileOutcome::Succeeded => Some("intent processed and status refreshed".to_owned()),
		ReconcileOutcome::RecoverableFailure => Some("recoverable reconciliation failure".to_owned()),
	};

	ReconcileAssessment {
		intent,
		outcome,
		message,
		action: Action::await_change(),
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
