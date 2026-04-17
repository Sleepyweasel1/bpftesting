 use std::{net::{IpAddr, Ipv4Addr}, str::FromStr, sync::Arc};

use aya::maps::{HashMap as BpfHashMap, MapData};
use tokio::sync::Mutex;
use tonic::{Request, Response, Status};

use crate::holdpacket::{
    capturelist_service_server::CapturelistService, AddRuleRequest, ListRulesRequest,
    ListRulesResponse, RemoveRuleRequest, RuleResponse,
};

pub struct CapturelistServer {
    pub capturelist_v4: Arc<Mutex<BpfHashMap<MapData, u32, u32>>>,
    pub capturelist_v6: Arc<Mutex<BpfHashMap<MapData, u128, u32>>>,
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
                self.capturelist_v4.lock().await.insert(addr, 0, 0)
                    .map_err(|e| Status::internal(format!("map insert failed: {e}")))?;
            }
            IpAddr::V6(v6) => {
                let addr: u128 = v6.into();
                self.capturelist_v6.lock().await.insert(addr, 0, 0)
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
                self.capturelist_v4.lock().await.remove(&addr)
                    .map_err(|e| Status::internal(format!("map remove failed: {e}")))?;
            }
            IpAddr::V6(v6) => {
                let addr: u128 = v6.into();
                self.capturelist_v6.lock().await.remove(&addr)
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
        let v4_map = self.capturelist_v4.lock().await;
        let mut ips: Vec<String> = v4_map
            .keys()
            .filter_map(|r| r.ok())
            .map(|addr| Ipv4Addr::from(addr).to_string())
            .collect();
        let v6_map = self.capturelist_v6.lock().await;
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
}


