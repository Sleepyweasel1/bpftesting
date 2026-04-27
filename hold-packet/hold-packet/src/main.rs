use std::{net::{Ipv4Addr, Ipv6Addr}, sync::Arc};

use aya::{
    maps::{Array, HashMap, MapData},
    programs::{LinkOrder, SchedClassifier, TcAttachType, tc},
};
use clap::Parser;
use hold_packet_common::StateEntry;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::sync::{Mutex, RwLock};
use tokio::time::Duration;
use tonic::transport::Server;

use grpc::CapturelistServer;
use holdpacket::capturelist_service_server::CapturelistServiceServer;
mod replay;
mod grpc;

pub mod holdpacket {
    tonic::include_proto!("holdpacket");
}

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
    #[clap(long, default_value = "[::]:50051")]
    grpc_addr: String,
    /// Seconds of inactivity before an IP is flagged for replay (service has scaled
    /// to zero). Once flagged, new inbound connections are redirected to the tap so
    /// the service can be woken up. Defaults to 300 s (5 minutes).
    #[clap(long, default_value = "300")]
    idle_timeout_secs: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/hold-packet"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
    let Opt { iface, grpc_addr, idle_timeout_secs } = opt;
    // error adding clsact to the interface if it is already added is harmless
    // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.
    // let _ = tc::qdisc_add_clsact(&iface);
    let program: &mut SchedClassifier = ebpf.program_mut("hold_packet").unwrap().try_into()?;
    program.load()?;
    program.attach_with_options(&iface, TcAttachType::Ingress, tc::TcAttachOptions::TcxOrder(LinkOrder::first()))?;

    // Take ownership of the CAPTURELIST map so it can be shared with the gRPC service.

    let statelistv6_map = ebpf
        .take_map("STATEV6")
        .expect("STATEV6 map not found");
    let statelistv6: HashMap<_, u128, StateEntry> = HashMap::try_from(statelistv6_map)?;
    let statelistv4_map = ebpf
        .take_map("STATEV4")
        .expect("STATEV4 map not found");
    let statelistv4: HashMap<_, u32, StateEntry> = HashMap::try_from(statelistv4_map)?;
    let shared_statelistv6 = Arc::new(RwLock::new(statelistv6));
    let shared_statelistv4 = Arc::new(RwLock::new(statelistv4));
    let tap_ifindex_map = ebpf
        .take_map("TAP_IFINDEX")
        .expect("TAP_IFINDEX map not found");
    let mut tap_ifindex: Array<_, u32> = Array::try_from(tap_ifindex_map)?;

    spawn_idle_monitor(
        Arc::clone(&shared_statelistv4),
        Arc::clone(&shared_statelistv6),
        idle_timeout_secs,
    );
    //start the replay task that will replay captured packets for IPs in the replay list
    let replayer = replay::Replayer::new("tap1")?;
    tap_ifindex.set(0, replayer.tap_ifindex(), 0)?;
    //start a task to have the replayer watch for packets sent to the tap
    // tokio::task::spawn(async move {
    //     replayer.run().await;
    // });
    replayer.spawn_pruner();
    let replayer =Arc::new(replayer);
    Arc::clone(&replayer).spawn_runner();
    //spawn pruner task to have the replayer automatically drop staged packets after the TTL expires

    // Start the gRPC control-plane server.
    let grpc_addr = grpc_addr.parse()?;
    let svc = CapturelistServiceServer::new(CapturelistServer {
            state_v4: Arc::clone(&shared_statelistv4),
            state_v6: Arc::clone(&shared_statelistv6),
            replayer: Arc::clone(&replayer),
    });
    tokio::task::spawn(async move {
        if let Err(e) = Server::builder().add_service(svc).serve(grpc_addr).await {
            eprintln!("gRPC server error: {e}");
        }
    });
    log::info!("gRPC server listening on {grpc_addr}");

    println!("Waiting for Ctrl-C...");
    tokio::signal::ctrl_c().await?;
    println!("Exiting...");

    Ok(())
}

/// Returns the current CLOCK_MONOTONIC time in nanoseconds, matching the
/// clock used by `bpf_ktime_get_ns()` in the eBPF program.
fn current_monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    (ts.tv_sec as u64) * 1_000_000_000 + ts.tv_nsec as u64
}

/// Spawns a background task that iterates over the capture-list maps every 30 s.
///
/// **Idle → scale-to-zero**: if an IP's last-seen timestamp is non-zero and
/// older than `idle_timeout_secs`, its replay-list entry is set to `true`.
/// The capture-list entry is kept so the eBPF program continues capturing
/// packets (which will now be redirected to the tap to wake the service).
///
/// **Active → service restored**: if an IP is currently in the replay list
/// but its timestamp has been updated within the idle window, the replay
/// flag is cleared (`false` / removed) so normal forwarding resumes.
pub fn calculate_state_updates<K: Copy>(
    entries: impl Iterator<Item = (K, StateEntry)>,
    now_ns: u64,
    idle_timeout_ns: u64,
) -> Vec<(K, StateEntry)> {
    entries
        .filter_map(|(ip, entry)| {
            if entry.last_seen_ns == 0 { return None; }
            let idle_time = now_ns.saturating_sub(entry.last_seen_ns);
            if idle_time > idle_timeout_ns && entry.replay != 1 {
                Some((ip, StateEntry { replay: 1, ..entry }))
            } else if idle_time <= idle_timeout_ns && entry.replay == 1 {
                Some((ip, StateEntry { replay: 0, ..entry }))
            } else {
                None
            }
        })
        .collect()
}

fn spawn_idle_monitor(
    statelist_v4: Arc<RwLock<HashMap<MapData, u32, StateEntry>>>,
    statelist_v6: Arc<RwLock<HashMap<MapData, u128, StateEntry>>>,
    idle_timeout_secs: u64,
) {
    let idle_timeout_ns = idle_timeout_secs.saturating_mul(1_000_000_000);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(30));
        loop {
            ticker.tick().await;
            let now_ns = current_monotonic_ns();
            
            let updates: Vec<(u32, StateEntry)> = {
                let v4_map = statelist_v4.read().await;
                calculate_state_updates(v4_map.iter().filter_map(|r| r.ok()), now_ns, idle_timeout_ns)
            }; // read lock dropped here

            // Write phase — lock held only for brief syscall bursts
            if !updates.is_empty() {
                let mut v4_map = statelist_v4.write().await;
                for (ip, entry) in updates {
                    v4_map.insert(ip, entry, 0).ok();
                }
            }
        
            let updates_v6: Vec<(u128, StateEntry)> = {
                let v6_map = statelist_v6.read().await;
                calculate_state_updates(v6_map.iter().filter_map(|r| r.ok()), now_ns, idle_timeout_ns)
            }; // read lock dropped here

            // Write phase — lock held only for brief syscall bursts
            if !updates_v6.is_empty() {
                let mut v6_map = statelist_v6.write().await;
                for (ip, entry) in updates_v6 {
                    v6_map.insert(ip, entry, 0).ok();
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_state_updates_no_change() {
        let entries = vec![
            (1u32, StateEntry { last_seen_ns: 1000, replay: 0, ..unsafe { std::mem::zeroed() } }),
            (2u32, StateEntry { last_seen_ns: 1000, replay: 1, ..unsafe { std::mem::zeroed() } }),
        ];
        // For IP 1, idle time = 2000 - 1000 = 1000, idle_timeout = 2000. Not idle. No change since replay is 0.
        // For IP 2, idle time = 4000 - 1000 = 3000, idle_timeout = 2000. Idle. No change since replay is already 1.
        let now_ns = 2000;
        let idle_timeout_ns = 2000;
        
        // Let's test IP 1 separately
        let updates = calculate_state_updates(vec![entries[0].clone()].into_iter(), now_ns, idle_timeout_ns);
        assert!(updates.is_empty());

        let now_ns_2 = 4000;
        let updates = calculate_state_updates(vec![entries[1].clone()].into_iter(), now_ns_2, idle_timeout_ns);
        assert!(updates.is_empty());
    }

    #[test]
    fn test_calculate_state_updates_to_idle() {
        let entries = vec![
            (1u32, StateEntry { last_seen_ns: 1000, replay: 0, ..unsafe { std::mem::zeroed() } }),
        ];
        let now_ns = 4000;
        let idle_timeout_ns = 2000;
        
        let updates = calculate_state_updates(entries.into_iter(), now_ns, idle_timeout_ns);
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].0, 1u32);
        assert_eq!(updates[0].1.replay, 1);
    }

    #[test]
    fn test_calculate_state_updates_to_active() {
        let entries = vec![
            (1u32, StateEntry { last_seen_ns: 3000, replay: 1, ..unsafe { std::mem::zeroed() } }),
        ];
        let now_ns = 4000;
        let idle_timeout_ns = 2000;
        
        let updates = calculate_state_updates(entries.into_iter(), now_ns, idle_timeout_ns);
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].0, 1u32);
        assert_eq!(updates[0].1.replay, 0);
    }

    #[test]
    fn test_calculate_state_updates_ignore_zero_last_seen() {
        let entries = vec![
            (1u32, StateEntry { last_seen_ns: 0, replay: 0, ..unsafe { std::mem::zeroed() } }),
        ];
        let now_ns = 4000;
        let idle_timeout_ns = 2000;
        
        let updates = calculate_state_updates(entries.into_iter(), now_ns, idle_timeout_ns);
        assert!(updates.is_empty());
    }
}
