 use std::{net::{IpAddr, Ipv4Addr}, str::FromStr, sync::{Arc}};

use aya::maps::{HashMap as BpfHashMap, MapData};
use tonic::{Request, Response, Status};
use hold_packet_common::StateEntry;
use crate::{holdpacket::{
    AddRuleRequest, ListRulesRequest, ListRulesResponse, RemoveRuleRequest, ReplayRuleRequest, RuleResponse, capturelist_service_server::CapturelistService
}, replay};
use tokio::sync::RwLock;

pub struct CapturelistServer {
    pub state_v4: Arc<RwLock<BpfHashMap<MapData, u32, StateEntry>>>,
    pub state_v6: Arc<RwLock<BpfHashMap<MapData, u128, StateEntry>>>,
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
        match ip {
            IpAddr::V4(v4) => {
                let addr: u32 = v4.into();
                let mut state_v4 = self.state_v4.write().await;
                state_v4.insert(addr, StateEntry::default(), 0)
                    .map_err(|e| Status::internal(format!("map insert failed: {e}")))?;
            }
            IpAddr::V6(v6) => {
                let addr: u128 = v6.into();
                let mut state_v6 = self.state_v6.write().await;
                state_v6.insert(addr, StateEntry::default(), 0)
                    .map_err(|e| Status::internal(format!("map insert failed: {e}")))?;
            }
        }        
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
        match ip {
            IpAddr::V4(v4) => {
                let addr: u32 = v4.into();
                let mut state_v4 = self.state_v4.write().await;
                state_v4.remove(&addr)
                    .map_err(|e| Status::internal(format!("map remove failed: {e}")))?;
            }
            IpAddr::V6(v6) => {
                let addr: u128 = v6.into();
                let mut state_v6 = self.state_v6.write().await;
                state_v6.remove(&addr)
                    .map_err(|e| Status::internal(format!("map remove failed: {e}")))?;
            }
        }

        Ok(Response::new(RuleResponse {
            success: true,
            error: String::new(),
        }))
    }

    async fn list_rules(
        &self,
        _request: Request<ListRulesRequest>,
    ) -> Result<Response<ListRulesResponse>, Status> {
        let v4_map = self.state_v4.read().await;
        let mut ips: Vec<String> = v4_map
            .keys()
            .filter_map(|r| r.ok())
            .map(|addr| Ipv4Addr::from(addr).to_string())
            .collect();
        let v6_map = self.state_v6.read().await;
        let ips_v6: Vec<String> = v6_map
            .keys()
            .filter_map(|r| r.ok())
            .map(|addr| {
                let bytes = addr.to_be_bytes();
                let ipv6 = std::net::Ipv6Addr::from(bytes);
                ipv6.to_string()
            })
            .collect();
        ips.extend(ips_v6);
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


