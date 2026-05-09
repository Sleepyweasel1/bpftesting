use std::{net::IpAddr, pin::Pin};

use tokio_stream::{Stream, StreamExt, wrappers::{BroadcastStream, errors::BroadcastStreamRecvError}};
use tonic::{Request, Response, Status};
use hold_packet_common::StateEntry;
use crate::{holdpacket::{
    AddRuleRequest, ListRulesRequest, ListRulesResponse, RemoveRuleRequest, ReplayRuleRequest,
    RuleResponse, StagedEvent as ProtoStagedEvent, WatchStagedPacketsRequest,
    capturelist_service_server::CapturelistService,
}, replay, capture_store::CaptureStore};
use std::sync::Arc;

pub struct CapturelistServer {
    pub capture_store: Arc<CaptureStore>,
    pub replayer: Arc<replay::Replayer>,
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


