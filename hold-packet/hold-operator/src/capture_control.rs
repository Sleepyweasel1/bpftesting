use std::{
	net::{AddrParseError, IpAddr},
	sync::Mutex,
	time::Duration,
};
#[cfg(test)]
use std::collections::VecDeque;

use async_trait::async_trait;
use futures::{StreamExt, stream::{BoxStream, iter, pending}};
use tonic::transport::Endpoint;

use crate::holdpacket::{
	AddRuleRequest, CaptureMode, GetIdleStatusRequest, IdleCaptureStatus as ProtoIdleCaptureStatus,
	ListRulesRequest, RemoveRuleRequest, ReplayRuleRequest,
	WatchStagedPacketsRequest,
	capturelist_service_client::CapturelistServiceClient,
};

const RPC_TIMEOUT: Duration = Duration::from_secs(2);

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum CaptureControlError {
	Transient(String),
	Permanent(String),
	NotFound(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedEvent {
	pub id: u64,
	pub src_ip: IpAddr,
	pub dst_ip: IpAddr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdleStatusKind {
	Active,
	Idle,
	UnknownNotCaptured,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdleStatus {
	pub ip: IpAddr,
	pub status: IdleStatusKind,
	pub last_seen_ns: u64,
	pub packet_count: u64,
	pub exceeds_idle_timeout: bool,
	pub mode: IdleStatusMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdleStatusMode {
	PassThrough,
	Hold,
	Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdleStatusSnapshot {
	pub idle_timeout_ns: u64,
	pub statuses: Vec<IdleStatus>,
}

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

#[async_trait]
pub trait CaptureControl: Send + Sync {
	async fn add_rule(&self, ip: IpAddr) -> Result<(), CaptureControlError>;
	async fn remove_rule(&self, ip: IpAddr) -> Result<(), CaptureControlError>;
	async fn list_rules(&self) -> Result<Vec<IpAddr>, CaptureControlError>;
	async fn get_idle_statuses(&self, ips: &[IpAddr]) -> Result<IdleStatusSnapshot, CaptureControlError>;
	async fn replay_rule(&self, id: u64) -> Result<(), CaptureControlError>;
	async fn watch_staged(&self) -> Result<BoxStream<'static, StagedEvent>, CaptureControlError>;
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

	async fn get_idle_statuses(&self, ips: &[IpAddr]) -> Result<IdleStatusSnapshot, CaptureControlError> {
		let mut client = self.connect().await?;
		let response = client
			.get_idle_status(GetIdleStatusRequest {
				ips: ips.iter().map(ToString::to_string).collect(),
			})
			.await
			.map_err(classify_status)?;

		let body = response.into_inner();
		let statuses = body
			.statuses
			.into_iter()
			.map(parse_idle_status)
			.collect::<Result<Vec<_>, _>>()?;

		Ok(IdleStatusSnapshot {
			idle_timeout_ns: body.idle_timeout_ns,
			statuses,
		})
	}

	async fn replay_rule(&self, id: u64) -> Result<(), CaptureControlError> {
		let mut client = self.connect().await?;
		let response = client
			.replay_rule(ReplayRuleRequest { id })
			.await
			.map_err(classify_status)?;
		check_response(response.into_inner())
	}

	async fn watch_staged(&self) -> Result<BoxStream<'static, StagedEvent>, CaptureControlError> {
		let mut client = self.connect().await?;
		let response = client
			.watch_staged_packets(WatchStagedPacketsRequest {})
			.await
			.map_err(classify_status)?;

		let stream = response.into_inner().filter_map(|item| async move {
			match item {
				Ok(event) => match parse_staged_event(event) {
					Ok(parsed) => Some(parsed),
					Err(error) => {
						log::warn!("dropping malformed staged event from hold-packet agent: {:?}", error);
						None
					}
				},
				Err(status) => {
					log::warn!("dropping staged event due to stream status error: {}", status);
					None
				}
			}
		});

		Ok(Box::pin(stream))
	}
}

fn classify_status(status: tonic::Status) -> CaptureControlError {
	match status.code() {
		tonic::Code::NotFound => {
			CaptureControlError::NotFound(format!("hold-packet agent resource not found: {status}"))
		}
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

fn parse_staged_event(event: crate::holdpacket::StagedEvent) -> Result<StagedEvent, CaptureControlError> {
	let src_ip = event
		.src_ip
		.parse::<IpAddr>()
		.map_err(|e: AddrParseError| {
			CaptureControlError::Permanent(format!(
				"hold-packet agent returned invalid staged src_ip {:?}: {}",
				event.src_ip, e
			))
		})?;
	let dst_ip = event
		.dst_ip
		.parse::<IpAddr>()
		.map_err(|e: AddrParseError| {
			CaptureControlError::Permanent(format!(
				"hold-packet agent returned invalid staged dst_ip {:?}: {}",
				event.dst_ip, e
			))
		})?;

	Ok(StagedEvent {
		id: event.id,
		src_ip,
		dst_ip,
	})
}

fn parse_idle_status(event: crate::holdpacket::IpIdleStatus) -> Result<IdleStatus, CaptureControlError> {
	let ip = event.ip.parse::<IpAddr>().map_err(|e: AddrParseError| {
		CaptureControlError::Permanent(format!(
			"hold-packet agent returned invalid idle status ip {:?}: {}",
			event.ip, e
		))
	})?;

	let status = match ProtoIdleCaptureStatus::try_from(event.status).map_err(|_| {
		CaptureControlError::Permanent(format!(
			"hold-packet agent returned invalid idle status discriminant {} for ip {}",
			event.status, ip
		))
	})? {
		ProtoIdleCaptureStatus::Active => IdleStatusKind::Active,
		ProtoIdleCaptureStatus::Idle => IdleStatusKind::Idle,
		ProtoIdleCaptureStatus::UnknownNotCaptured
		| ProtoIdleCaptureStatus::Unspecified => IdleStatusKind::UnknownNotCaptured,
	};

	let mode = match CaptureMode::try_from(event.mode).map_err(|_| {
		CaptureControlError::Permanent(format!(
			"hold-packet agent returned invalid capture mode discriminant {} for ip {}",
			event.mode, ip
		))
	})? {
		CaptureMode::PassThrough => IdleStatusMode::PassThrough,
		CaptureMode::Hold => IdleStatusMode::Hold,
		CaptureMode::Unspecified => IdleStatusMode::Unknown,
	};

	Ok(IdleStatus {
		ip,
		status,
		last_seen_ns: event.last_seen_ns,
		packet_count: event.packet_count,
		exceeds_idle_timeout: event.exceeds_idle_timeout,
		mode,
	})
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
	pub listed_rules: Mutex<Vec<IpAddr>>,
	pub idle_statuses: Mutex<Vec<IdleStatus>>,
	pub idle_timeout_ns: Mutex<u64>,
	pub staged_events: Mutex<Vec<StagedEvent>>,
	pub replay_results: Mutex<VecDeque<Result<(), CaptureControlError>>>,
	pub watch_error: Mutex<Option<CaptureControlError>>,
	pub idle_error: Mutex<Option<CaptureControlError>>,
}

#[cfg(test)]
impl FakeCaptureControl {
	pub fn new() -> Self {
		Self {
			add_calls: Mutex::new(Vec::new()),
			remove_calls: Mutex::new(Vec::new()),
			replay_calls: Mutex::new(Vec::new()),
			listed_rules: Mutex::new(Vec::new()),
			idle_statuses: Mutex::new(Vec::new()),
			idle_timeout_ns: Mutex::new(0),
			staged_events: Mutex::new(Vec::new()),
			replay_results: Mutex::new(VecDeque::new()),
			watch_error: Mutex::new(None),
			idle_error: Mutex::new(None),
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
		Ok(self.listed_rules.lock().unwrap().clone())
	}

	async fn get_idle_statuses(&self, ips: &[IpAddr]) -> Result<IdleStatusSnapshot, CaptureControlError> {
		if let Some(error) = self.idle_error.lock().unwrap().take() {
			return Err(error);
		}

		let configured = self.idle_statuses.lock().unwrap().clone();
		let statuses = ips
			.iter()
			.map(|ip| {
				configured
					.iter()
					.find(|status| status.ip == *ip)
					.cloned()
					.unwrap_or(IdleStatus {
						ip: *ip,
						status: IdleStatusKind::UnknownNotCaptured,
						last_seen_ns: 0,
						packet_count: 0,
						exceeds_idle_timeout: false,
						mode: IdleStatusMode::Unknown,
					})
			})
			.collect();

		Ok(IdleStatusSnapshot {
			idle_timeout_ns: *self.idle_timeout_ns.lock().unwrap(),
			statuses,
		})
	}

	async fn replay_rule(&self, id: u64) -> Result<(), CaptureControlError> {
		self.replay_calls.lock().unwrap().push(id);
		if let Some(result) = self.replay_results.lock().unwrap().pop_front() {
			return result;
		}
		Ok(())
	}

	async fn watch_staged(&self) -> Result<BoxStream<'static, StagedEvent>, CaptureControlError> {
		if let Some(error) = self.watch_error.lock().unwrap().take() {
			return Err(error);
		}

		let events = self.staged_events.lock().unwrap().clone();
		let stream = iter(events).chain(pending());
		Ok(Box::pin(stream))
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
