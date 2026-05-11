use std::{net::IpAddr, pin::Pin};

use tokio_stream::{Stream, StreamExt, wrappers::{BroadcastStream, errors::BroadcastStreamRecvError}};
use tonic::{Request, Response, Status};
use hold_packet_common::{CaptureMode, StateEntry};
use crate::{holdpacket::{
    AddRuleRequest, CaptureMode as ProtoCaptureMode, GetIdleStatusRequest, GetIdleStatusResponse,
    IdleCaptureStatus, IpIdleStatus, ListRulesRequest, ListRulesResponse, RemoveRuleRequest, ReplayRuleRequest,
    RuleResponse, StagedEvent as ProtoStagedEvent, WatchStagedPacketsRequest,
    capturelist_service_server::CapturelistService,
}, replay, capture_store::CaptureStore};
use std::sync::Arc;

pub struct CapturelistServer {
    pub capture_store: Arc<CaptureStore>,
    pub replayer: Arc<replay::Replayer>,
    pub idle_timeout_ns: u64,
}

fn map_idle_status(ip: IpAddr, entry: Option<StateEntry>) -> IpIdleStatus {
    match entry {
        Some(state_entry) => {
            let is_idle = state_entry.mode == CaptureMode::Hold;
            let status = if is_idle {
                IdleCaptureStatus::Idle
            } else {
                IdleCaptureStatus::Active
            };
            let mode = if is_idle {
                ProtoCaptureMode::Hold
            } else {
                ProtoCaptureMode::PassThrough
            };

            IpIdleStatus {
                ip: ip.to_string(),
                status: status as i32,
                last_seen_ns: state_entry.last_seen_ns,
                packet_count: state_entry.packet_count,
                mode: mode as i32,
                exceeds_idle_timeout: is_idle,
            }
        }
        None => IpIdleStatus {
            ip: ip.to_string(),
            status: IdleCaptureStatus::UnknownNotCaptured as i32,
            last_seen_ns: 0,
            packet_count: 0,
            mode: ProtoCaptureMode::Unspecified as i32,
            exceeds_idle_timeout: false,
        },
    }
}

#[tonic::async_trait]
impl CapturelistService for CapturelistServer {
    type WatchStagedPacketsStream = Pin<Box<dyn Stream<Item = Result<ProtoStagedEvent, Status>> + Send + 'static>>;

    async fn add_rule(
        &self,
        request: Request<AddRuleRequest>,
    ) -> Result<Response<RuleResponse>, Status> {
        let ip_str = request.into_inner().ip;
        let ip: IpAddr = ip_str.parse()
            .map_err(|e| Status::invalid_argument(format!("invalid IP: {e}")))?;
        
        self.capture_store.insert(ip, StateEntry::default()).await
            .map_err(|e| Status::internal(e.to_string()))?;
        
        Ok(Response::new(RuleResponse {
            success: true,
            error: String::new(),
        }))
    }

    async fn remove_rule(
        &self,
        request: Request<RemoveRuleRequest>,
    ) -> Result<Response<RuleResponse>, Status> {
        let ip_str = request.into_inner().ip;
        let ip: IpAddr = ip_str.parse()
            .map_err(|e| Status::invalid_argument(format!("invalid IP: {e}")))?;
        
        self.capture_store.remove(ip).await
            .map_err(|e| Status::internal(e.to_string()))?;
        
        Ok(Response::new(RuleResponse {
            success: true,
            error: String::new(),
        }))
    }

    async fn list_rules(
        &self,
        _request: Request<ListRulesRequest>,
    ) -> Result<Response<ListRulesResponse>, Status> {
        let all_entries = self.capture_store.iter().await;
        let ips: Vec<String> = all_entries
            .into_iter()
            .map(|(ip, _entry)| ip.to_string())
            .collect();
        Ok(Response::new(ListRulesResponse { ips }))
    }

    async fn get_idle_status(
        &self,
        request: Request<GetIdleStatusRequest>,
    ) -> Result<Response<GetIdleStatusResponse>, Status> {
        let mut statuses = Vec::new();

        for ip_str in request.into_inner().ips {
            let ip: IpAddr = ip_str
                .parse()
                .map_err(|e| Status::invalid_argument(format!("invalid IP {ip_str:?}: {e}")))?;
            let entry = self
                .capture_store
                .get(ip)
                .await
                .map_err(|e| Status::internal(e.to_string()))?;

            statuses.push(map_idle_status(ip, entry));
        }

        Ok(Response::new(GetIdleStatusResponse {
            idle_timeout_ns: self.idle_timeout_ns,
            statuses,
        }))
    }

    async fn watch_staged_packets(
        &self,
        _request: Request<WatchStagedPacketsRequest>,
    ) -> Result<Response<Self::WatchStagedPacketsStream>, Status> {
        let stream = BroadcastStream::new(self.replayer.subscribe()).filter_map(|result| {
            match result {
                Ok(event) => Some(Ok(ProtoStagedEvent {
                    id: event.id,
                    src_ip: event.src_ip.to_string(),
                    dst_ip: event.dst_ip.to_string(),
                })),
                Err(BroadcastStreamRecvError::Lagged(skipped)) => {
                    log::warn!("dropping {skipped} staged packet events due to slow stream consumer");
                    None
                }
            }
        });

        Ok(Response::new(Box::pin(stream)))
    }

    async fn replay_rule (&self, request: Request<ReplayRuleRequest>) -> Result<Response<RuleResponse>, Status> {
        let id = request.into_inner().id;
        self.replayer.replay_staged(id).await
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    Status::not_found(format!("staged packet not found: {e}"))
                } else {
                    Status::internal(format!("failed to replay staged packet: {e}"))
                }
            })?;
        Ok(
            Response::new(RuleResponse {
                success: true,
                error: String::new(),
            })
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_idle_status_reports_active_entry() {
        let ip: IpAddr = "10.96.0.1".parse().unwrap();
        let status = map_idle_status(
            ip,
            Some(StateEntry {
                last_seen_ns: 111,
                packet_count: 5,
                mode: CaptureMode::PassThrough,
            }),
        );

        assert_eq!(status.ip, "10.96.0.1");
        assert_eq!(status.status, IdleCaptureStatus::Active as i32);
        assert_eq!(status.mode, ProtoCaptureMode::PassThrough as i32);
        assert!(!status.exceeds_idle_timeout);
    }

    #[test]
    fn map_idle_status_reports_idle_entry() {
        let ip: IpAddr = "fd00::1".parse().unwrap();
        let status = map_idle_status(
            ip,
            Some(StateEntry {
                last_seen_ns: 222,
                packet_count: 9,
                mode: CaptureMode::Hold,
            }),
        );

        assert_eq!(status.status, IdleCaptureStatus::Idle as i32);
        assert_eq!(status.mode, ProtoCaptureMode::Hold as i32);
        assert!(status.exceeds_idle_timeout);
    }

    #[test]
    fn map_idle_status_reports_unknown_not_captured() {
        let ip: IpAddr = "10.96.0.44".parse().unwrap();
        let status = map_idle_status(ip, None);

        assert_eq!(status.status, IdleCaptureStatus::UnknownNotCaptured as i32);
        assert_eq!(status.mode, ProtoCaptureMode::Unspecified as i32);
        assert_eq!(status.last_seen_ns, 0);
        assert_eq!(status.packet_count, 0);
        assert!(!status.exceeds_idle_timeout);
    }
}


