use std::sync::Arc;

use futures::StreamExt;
use kube::{
	Api, Client, ResourceExt,
	runtime::{
		Controller,
		controller::Action,
		watcher,
	},
};
use log::{error, info};

use hold_operator::stz::ScaleToZero;

#[derive(Clone, Default)]
struct OperatorContext;

#[tokio::main]
async fn main() -> Result<(), kube::Error> {
	env_logger::init();

	info!("starting hold-operator controller");

	let client = Client::try_default().await?;
	let stz_api: Api<ScaleToZero> = Api::all(client);

	Controller::new(stz_api, watcher::Config::default())
		.run(reconcile, error_policy, Arc::new(OperatorContext))
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

async fn reconcile(stz: Arc<ScaleToZero>, _ctx: Arc<OperatorContext>) -> Result<Action, kube::Error> {
	let namespace = stz.namespace().unwrap_or_else(|| "<cluster>".to_owned());
	info!(
		"reconciling ScaleToZero: namespace={} name={}",
		namespace,
		stz.name_any()
	);

	// Starter loop behavior: observe resources and exit cleanly without mutating state.
	Ok(Action::await_change())
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
