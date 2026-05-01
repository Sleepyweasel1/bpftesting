 use std::net::IpAddr;

use tonic::{Request, Response, Status};
use hold_packet_common::StateEntry;
use crate::{holdpacket::{
    AddRuleRequest, ListRulesRequest, ListRulesResponse, RemoveRuleRequest, ReplayRuleRequest, RuleResponse, capturelist_service_server::CapturelistService
}, replay, capture_store::CaptureStore};
use std::sync::Arc;

pub struct CapturelistServer {
    pub capture_store: Arc<CaptureStore>,
    pub replayer: Arc<replay::Replayer>,
}

#[tonic::async_trait]
impl CapturelistService for CapturelistServer {
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
    async fn replay_rule (&self, request: Request<ReplayRuleRequest>) -> Result<Response<RuleResponse>, Status> {
        let id = request.into_inner().id;
        self.replayer.replay_staged(id).await
            .map_err(|e| Status::internal(format!("failed to replay staged packet: {e}")))?;
        Ok(
            Response::new(RuleResponse {
                success: true,
                error: String::new(),
            })
        )
    }
}


