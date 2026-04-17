 use std::{net::Ipv4Addr, str::FromStr, sync::Arc};

use aya::maps::{HashMap as BpfHashMap, MapData};
use tokio::sync::Mutex;
use tonic::{Request, Response, Status};

use crate::holdpacket::{
    blocklist_service_server::BlocklistService, AddRuleRequest, ListRulesRequest,
    ListRulesResponse, RemoveRuleRequest, RuleResponse,
};

pub struct BlocklistServer {
    pub blocklist: Arc<Mutex<BpfHashMap<MapData, u32, u32>>>,
}

#[tonic::async_trait]
impl BlocklistService for BlocklistServer {
    async fn add_rule(
        &self,
        request: Request<AddRuleRequest>,
    ) -> Result<Response<RuleResponse>, Status> {
        let ip_str = request.into_inner().ip;
        let ip = Ipv4Addr::from_str(&ip_str)
            .map_err(|e| Status::invalid_argument(format!("invalid IP: {e}")))?;
        let addr: u32 = ip.into();
        self.blocklist
            .lock()
            .await
            .insert(addr, 0, 0)
            .map_err(|e| Status::internal(format!("map insert failed: {e}")))?;
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
        let ip = Ipv4Addr::from_str(&ip_str)
            .map_err(|e| Status::invalid_argument(format!("invalid IP: {e}")))?;
        let addr: u32 = ip.into();
        self.blocklist
            .lock()
            .await
            .remove(&addr)
            .map_err(|e| Status::internal(format!("map remove failed: {e}")))?;
        Ok(Response::new(RuleResponse {
            success: true,
            error: String::new(),
        }))
    }

    async fn list_rules(
        &self,
        _request: Request<ListRulesRequest>,
    ) -> Result<Response<ListRulesResponse>, Status> {
        let map = self.blocklist.lock().await;
        let ips: Vec<String> = map
            .keys()
            .filter_map(|r| r.ok())
            .map(|addr| Ipv4Addr::from(addr).to_string())
            .collect();
        Ok(Response::new(ListRulesResponse { ips }))
    }
}
