use std::{
	net::{AddrParseError, IpAddr},
	sync::Mutex,
	time::Duration,
};

use async_trait::async_trait;
use tonic::transport::Endpoint;

use crate::holdpacket::{
	AddRuleRequest, ListRulesRequest, RemoveRuleRequest, ReplayRuleRequest,
	capturelist_service_client::CapturelistServiceClient,
};

const RPC_TIMEOUT: Duration = Duration::from_secs(2);

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum CaptureControlError {
	Transient(String),
	Permanent(String),
}

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

#[async_trait]
pub trait CaptureControl: Send + Sync {
	async fn add_rule(&self, ip: IpAddr) -> Result<(), CaptureControlError>;
	async fn remove_rule(&self, ip: IpAddr) -> Result<(), CaptureControlError>;
	async fn list_rules(&self) -> Result<Vec<IpAddr>, CaptureControlError>;
	async fn replay_rule(&self, id: u64) -> Result<(), CaptureControlError>;
}

// ---------------------------------------------------------------------------
// Real implementation
// ---------------------------------------------------------------------------

pub struct HoldPacketClient {
	endpoint: String,
}

impl HoldPacketClient {
	pub fn new(endpoint: String) -> Self {
		Self { endpoint }
	}

	async fn connect(
		&self,
	) -> Result<CapturelistServiceClient<tonic::transport::Channel>, CaptureControlError> {
		let endpoint = Endpoint::from_shared(self.endpoint.clone())
			.map_err(|e| {
				CaptureControlError::Permanent(format!("invalid hold-packet gRPC endpoint: {e}"))
			})?
			.connect_timeout(RPC_TIMEOUT)
			.timeout(RPC_TIMEOUT);

		let channel = endpoint.connect().await.map_err(|e| {
			CaptureControlError::Transient(format!(
				"failed to connect to hold-packet agent: {e}"
			))
		})?;

		Ok(CapturelistServiceClient::new(channel))
	}
}

#[async_trait]
impl CaptureControl for HoldPacketClient {
	async fn add_rule(&self, ip: IpAddr) -> Result<(), CaptureControlError> {
		let mut client = self.connect().await?;
		let response = client
			.add_rule(AddRuleRequest { ip: ip.to_string() })
			.await
			.map_err(classify_status)?;
		check_response(response.into_inner())
	}

	async fn remove_rule(&self, ip: IpAddr) -> Result<(), CaptureControlError> {
		let mut client = self.connect().await?;
		let response = client
			.remove_rule(RemoveRuleRequest { ip: ip.to_string() })
			.await
			.map_err(classify_status)?;
		check_response(response.into_inner())
	}

	async fn list_rules(&self) -> Result<Vec<IpAddr>, CaptureControlError> {
		let mut client = self.connect().await?;
		let response = client
			.list_rules(ListRulesRequest {})
			.await
			.map_err(classify_status)?;
		let ips = response.into_inner().ips;

		ips.iter()
			.map(|s| {
				s.parse::<IpAddr>().map_err(|e: AddrParseError| {
					CaptureControlError::Permanent(format!(
						"hold-packet agent returned invalid IP {s:?}: {e}"
					))
				})
			})
			.collect()
	}

	async fn replay_rule(&self, id: u64) -> Result<(), CaptureControlError> {
		let mut client = self.connect().await?;
		let response = client
			.replay_rule(ReplayRuleRequest { id })
			.await
			.map_err(classify_status)?;
		check_response(response.into_inner())
	}
}

fn classify_status(status: tonic::Status) -> CaptureControlError {
	match status.code() {
		tonic::Code::InvalidArgument
		| tonic::Code::FailedPrecondition
		| tonic::Code::Unimplemented => CaptureControlError::Permanent(format!(
			"hold-packet agent call failed permanently: {status}"
		)),
		tonic::Code::DeadlineExceeded => {
			CaptureControlError::Transient("hold-packet agent call timed out".to_owned())
		}
		_ => CaptureControlError::Transient(format!(
			"hold-packet agent call failed transiently: {status}"
		)),
	}
}

fn check_response(
	body: crate::holdpacket::RuleResponse,
) -> Result<(), CaptureControlError> {
	if body.success {
		Ok(())
	} else {
		Err(CaptureControlError::Transient(if body.error.is_empty() {
			"hold-packet agent returned unsuccessful response".to_owned()
		} else {
			format!("hold-packet agent rejected request: {}", body.error)
		}))
	}
}

// ---------------------------------------------------------------------------
// Test double
// ---------------------------------------------------------------------------

#[cfg(test)]
pub struct FakeCaptureControl {
	pub add_calls: Mutex<Vec<IpAddr>>,
	pub remove_calls: Mutex<Vec<IpAddr>>,
	pub replay_calls: Mutex<Vec<u64>>,
}

#[cfg(test)]
impl FakeCaptureControl {
	pub fn new() -> Self {
		Self {
			add_calls: Mutex::new(Vec::new()),
			remove_calls: Mutex::new(Vec::new()),
			replay_calls: Mutex::new(Vec::new()),
		}
	}
}

#[cfg(test)]
#[async_trait]
impl CaptureControl for FakeCaptureControl {
	async fn add_rule(&self, ip: IpAddr) -> Result<(), CaptureControlError> {
		self.add_calls.lock().unwrap().push(ip);
		Ok(())
	}

	async fn remove_rule(&self, ip: IpAddr) -> Result<(), CaptureControlError> {
		self.remove_calls.lock().unwrap().push(ip);
		Ok(())
	}

	async fn list_rules(&self) -> Result<Vec<IpAddr>, CaptureControlError> {
		Ok(vec![])
	}

	async fn replay_rule(&self, id: u64) -> Result<(), CaptureControlError> {
		self.replay_calls.lock().unwrap().push(id);
		Ok(())
	}
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
	use super::*;
	use std::sync::Arc;

	#[tokio::test]
	async fn add_rule_records_ip_and_formats_as_dotted_decimal() {
		let fake = Arc::new(FakeCaptureControl::new());
		let ip: IpAddr = "10.96.0.1".parse().unwrap();

		fake.add_rule(ip).await.expect("add_rule should succeed");

		let calls = fake.add_calls.lock().unwrap();
		assert_eq!(calls.len(), 1);

		// Verify the IpAddr round-trips to the dotted-decimal string that
		// HoldPacketClient would send on the wire (ip.to_string()).
		assert_eq!(calls[0].to_string(), "10.96.0.1");
	}

	#[tokio::test]
	async fn remove_rule_records_ip() {
		let fake = Arc::new(FakeCaptureControl::new());
		let ip: IpAddr = "192.168.1.100".parse().unwrap();

		fake.remove_rule(ip).await.expect("remove_rule should succeed");

		let calls = fake.remove_calls.lock().unwrap();
		assert_eq!(calls.len(), 1);
		assert_eq!(calls[0].to_string(), "192.168.1.100");
	}
}
