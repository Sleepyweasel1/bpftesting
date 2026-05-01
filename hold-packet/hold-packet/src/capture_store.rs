use std::net::IpAddr;
use aya::maps::{HashMap as BpfHashMap, MapData};
use hold_packet_common::StateEntry;
use tokio::sync::RwLock;
use std::sync::Arc;

/// Error type for CaptureStore operations.
#[derive(Debug, Clone)]
pub enum CaptureStoreError {
    /// Map insertion failed (e.g., capacity reached).
    InsertFailed(String),
    /// Map removal failed.
    RemoveFailed(String),
    /// Map retrieval failed.
    GetFailed(String),
}

impl std::fmt::Display for CaptureStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CaptureStoreError::InsertFailed(msg) => write!(f, "insert failed: {}", msg),
            CaptureStoreError::RemoveFailed(msg) => write!(f, "remove failed: {}", msg),
            CaptureStoreError::GetFailed(msg) => write!(f, "get failed: {}", msg),
        }
    }
}

impl std::error::Error for CaptureStoreError {}

/// Encapsulates dual IPv4/IPv6 eBPF state maps behind a unified interface.
/// 
/// The `CaptureStore` seam abstracts away the dual-map (`STATEV4`/`STATEV6`) split
/// that exists on the kernel side due to type constraints. Callers interact with
/// `IpAddr` keys and receive `StateEntry` values without branching on address family.
pub struct CaptureStore {
    state_v4: Arc<RwLock<BpfHashMap<MapData, u32, StateEntry>>>,
    state_v6: Arc<RwLock<BpfHashMap<MapData, u128, StateEntry>>>,
}

impl CaptureStore {
    /// Create a new CaptureStore from IPv4 and IPv6 map handles.
    pub fn new(
        state_v4: Arc<RwLock<BpfHashMap<MapData, u32, StateEntry>>>,
        state_v6: Arc<RwLock<BpfHashMap<MapData, u128, StateEntry>>>,
    ) -> Self {
        CaptureStore { state_v4, state_v6 }
    }

    /// Insert or update a captured IP with the given state entry.
    pub async fn insert(&self, ip: IpAddr, entry: StateEntry) -> Result<(), CaptureStoreError> {
        match ip {
            IpAddr::V4(v4) => {
                let addr: u32 = v4.into();
                let mut map = self.state_v4.write().await;
                map.insert(addr, entry, 0)
                    .map_err(|e| CaptureStoreError::InsertFailed(e.to_string()))?;
            }
            IpAddr::V6(v6) => {
                let addr: u128 = v6.into();
                let mut map = self.state_v6.write().await;
                map.insert(addr, entry, 0)
                    .map_err(|e| CaptureStoreError::InsertFailed(e.to_string()))?;
            }
        }
        Ok(())
    }

    /// Remove a captured IP from the store.
    pub async fn remove(&self, ip: IpAddr) -> Result<(), CaptureStoreError> {
        match ip {
            IpAddr::V4(v4) => {
                let addr: u32 = v4.into();
                let mut map = self.state_v4.write().await;
                map.remove(&addr)
                    .map_err(|e| CaptureStoreError::RemoveFailed(e.to_string()))?;
            }
            IpAddr::V6(v6) => {
                let addr: u128 = v6.into();
                let mut map = self.state_v6.write().await;
                map.remove(&addr)
                    .map_err(|e| CaptureStoreError::RemoveFailed(e.to_string()))?;
            }
        }
        Ok(())
    }

    /// Retrieve a captured IP's state entry, if present.
    /// Returns `Ok(None)` if the IP is not in the store (not an error).
    pub async fn get(&self, ip: IpAddr) -> Result<Option<StateEntry>, CaptureStoreError> {
        match ip {
            IpAddr::V4(v4) => {
                let addr: u32 = v4.into();
                let map = self.state_v4.read().await;
                match map.get(&addr, 0) {
                    Ok(entry) => Ok(Some(entry)),
                    Err(e) => {
                        let err_str = e.to_string();
                        // Check if this is a "key not found" error (common pattern in aya).
                        // If it's truly a retrieval error (not just missing key), treat as error.
                        if err_str.contains("not found") || err_str.contains("no entry") {
                            Ok(None)
                        } else {
                            Err(CaptureStoreError::GetFailed(err_str))
                        }
                    }
                }
            }
            IpAddr::V6(v6) => {
                let addr: u128 = v6.into();
                let map = self.state_v6.read().await;
                match map.get(&addr, 0) {
                    Ok(entry) => Ok(Some(entry)),
                    Err(e) => {
                        let err_str = e.to_string();
                        if err_str.contains("not found") || err_str.contains("no entry") {
                            Ok(None)
                        } else {
                            Err(CaptureStoreError::GetFailed(err_str))
                        }
                    }
                }
            }
        }
    }

    /// Return an eager snapshot of all captured IPs and their state entries.
    pub async fn iter(&self) -> Vec<(IpAddr, StateEntry)> {
        let mut result = Vec::new();

        // Snapshot IPv4
        {
            let map = self.state_v4.read().await;
            for entry_result in map.iter() {
                if let Ok((addr, entry)) = entry_result {
                    let ip = IpAddr::V4(addr.into());
                    result.push((ip, entry));
                }
            }
        }

        // Snapshot IPv6
        {
            let map = self.state_v6.read().await;
            for entry_result in map.iter() {
                if let Ok((addr, entry)) = entry_result {
                    let ip = IpAddr::V6(addr.into());
                    result.push((ip, entry));
                }
            }
        }

        result
    }

    /// Update only the capture mode for a given IP, preserving telemetry.
    /// Returns `Ok(true)` if the IP was found and updated.
    /// Returns `Ok(false)` if the IP was not found (idempotent no-op).
    /// Returns `Err` only on actual map operation failures.
    pub async fn update_mode(
        &self,
        ip: IpAddr,
        new_mode: hold_packet_common::CaptureMode,
    ) -> Result<bool, CaptureStoreError> {
        use hold_packet_common::CaptureMode;

        match ip {
            IpAddr::V4(v4) => {
                let addr: u32 = v4.into();
                let mut map = self.state_v4.write().await;
                match map.get(&addr, 0) {
                    Ok(mut entry) => {
                        entry.mode = new_mode;
                        map.insert(addr, entry, 0)
                            .map_err(|e| CaptureStoreError::InsertFailed(e.to_string()))?;
                        Ok(true)
                    }
                    Err(e) => {
                        let err_str = e.to_string();
                        if err_str.contains("not found") || err_str.contains("no entry") {
                            Ok(false) // Idempotent: IP not present
                        } else {
                            Err(CaptureStoreError::GetFailed(err_str))
                        }
                    }
                }
            }
            IpAddr::V6(v6) => {
                let addr: u128 = v6.into();
                let mut map = self.state_v6.write().await;
                match map.get(&addr, 0) {
                    Ok(mut entry) => {
                        entry.mode = new_mode;
                        map.insert(addr, entry, 0)
                            .map_err(|e| CaptureStoreError::InsertFailed(e.to_string()))?;
                        Ok(true)
                    }
                    Err(e) => {
                        let err_str = e.to_string();
                        if err_str.contains("not found") || err_str.contains("no entry") {
                            Ok(false)
                        } else {
                            Err(CaptureStoreError::GetFailed(err_str))
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // For unit tests without eBPF runtime, we create mock stores for demonstration.
    // Real integration tests will use live eBPF maps.
    
    #[test]
    fn test_capture_store_error_display() {
        let err = CaptureStoreError::InsertFailed("test error".to_string());
        assert_eq!(err.to_string(), "insert failed: test error");
    }

    #[test]
    fn test_ipaddr_ipv4_roundtrip() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let v4: Ipv4Addr = match ip {
            IpAddr::V4(v4) => v4,
            _ => panic!("expected IPv4"),
        };
        assert_eq!(v4.to_string(), "192.168.1.1");
    }

    #[test]
    fn test_ipaddr_ipv6_roundtrip() {
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        assert_eq!(ip.to_string(), "2001:db8::1");
    }

    #[test]
    fn test_state_entry_default() {
        let entry = StateEntry::default();
        assert_eq!(entry.last_seen_ns, 0);
        assert_eq!(entry.packet_count, 0);
    }

    #[test]
    fn test_state_entry_with_values() {
        use hold_packet_common::CaptureMode;
        let entry = StateEntry {
            last_seen_ns: 1000,
            packet_count: 42,
            mode: CaptureMode::Hold,
        };
        assert_eq!(entry.last_seen_ns, 1000);
        assert_eq!(entry.packet_count, 42);
        assert_eq!(entry.mode, CaptureMode::Hold);
    }

    #[test]
    fn test_ipaddr_v4_to_u32() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let v4: Ipv4Addr = match ip {
            IpAddr::V4(v4) => v4,
            _ => panic!("expected IPv4"),
        };
        let addr: u32 = v4.into();
        assert_eq!(addr, 0xc0a80101); // 192.168.1.1 in hex
    }

    #[test]
    fn test_ipaddr_v6_to_u128() {
        let ip = IpAddr::V6(Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8));
        let v6: Ipv6Addr = match ip {
            IpAddr::V6(v6) => v6,
            _ => panic!("expected IPv6"),
        };
        let addr: u128 = v6.into();
        assert!(addr > 0);
    }
}
