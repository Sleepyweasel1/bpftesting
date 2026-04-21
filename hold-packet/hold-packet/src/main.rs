use std::{net::Ipv4Addr, sync::Arc};

use aya::{
    maps::{HashMap, MapData},
    programs::{LinkOrder, SchedClassifier, TcAttachType, tc},
};
use clap::Parser;
use hold_packet_common::StateEntry;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::sync::Mutex;
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

    //TODO: simplify all this to the new StateEntry
    let statelistv6_map = ebpf
        .take_map("STATEV6")
        .expect("STATEV6 map not found");
    let statelistv6: HashMap<_, u128, StateEntry> = HashMap::try_from(statelistv6_map)?;
    let statelistv4_map = ebpf
        .take_map("STATEV4")
        .expect("STATEV4 map not found");
    let statelistv4: HashMap<_, u32, StateEntry> = HashMap::try_from(statelistv4_map)?;

    let shared_statelistv6 = Arc::new(Mutex::new(statelistv6));
    let shared_statelistv4 = Arc::new(Mutex::new(statelistv4));


    spawn_idle_monitor(
        Arc::clone(&shared_statelistv4);
        idle_timeout_secs,
    );

    // Start the gRPC control-plane server.
    let grpc_addr = grpc_addr.parse()?;
    let svc = CapturelistServiceServer::new(CapturelistServer {
        capturelist_v6: shared_capturelistv6,
        capturelist_v4: shared_capturelistv4,
        replaylist_v4: shared_replaylistv4,
        replaylist_v6: shared_replaylistv6,
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
fn spawn_idle_monitor(
    statelist_v4: Arc<Mutex<HashMap<MapData, u32, StateEntry>>>,
    statelist_v6: Arc<Mutex<HashMap<MapData, u128, StateEntry>>>,
    idle_timeout_secs: u64,
) {
    let idle_timeout_ns = idle_timeout_secs.saturating_mul(1_000_000_000);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(30));
        loop {
            ticker.tick().await;
            let now_ns = current_monotonic_ns();

            // --- IPv4 ---
            let entries_v4: Vec<(u32, StateEntry)> = statelist_v4
                .lock()
                .await
                .iter()
                .filter_map(|r| r.ok())
                .collect();
            for (addr, ts) in entries_v4 {
                let idle = ts.last_seen_ns > 0 && now_ns.saturating_sub(ts.last_seen_ns) >= idle_timeout_ns;
                if idle {
                    // Traffic has stopped — flag this IP for replay so new
                    // connections are held and the service can be woken up.
                    log::info!(
                        "idle-monitor: IPv4 {} idle for >{}s, enabling replay (scale-to-zero)",
                        std::net::Ipv4Addr::from(addr),
                        idle_timeout_secs
                    );
                    let _ = replaylist_v4.lock().await.insert(addr, 1u8, 0);
                } else {
                    // Traffic is flowing — if the replay flag is set, clear it
                    // because the service is back up.
                    let currently_replaying = replaylist_v4
                        .lock()
                        .await
                        .get(&addr, 0)
                        .ok()
                        .unwrap_or(0) != 0;
                    if currently_replaying {
                        log::info!(
                            "idle-monitor: IPv4 {} traffic resumed, disabling replay",
                            std::net::Ipv4Addr::from(addr)
                        );
                        let _ = replaylist_v4.lock().await.remove(&addr);
                    }
                }
            }

            // --- IPv6 ---
            let entries_v6: Vec<(u128, u64)> = capturelist_v6
                .lock()
                .await
                .iter()
                .filter_map(|r| r.ok())
                .collect();
            for (addr, ts) in entries_v6 {
                let idle = ts > 0 && now_ns.saturating_sub(ts) >= idle_timeout_ns;
                if idle {
                    log::info!(
                        "idle-monitor: IPv6 {} idle for >{}s, enabling replay (scale-to-zero)",
                        std::net::Ipv6Addr::from(addr),
                        idle_timeout_secs
                    );
                    let _ = replaylist_v6.lock().await.insert(addr, 1u8, 0);
                } else {
                    let currently_replaying = replaylist_v6
                        .lock()
                        .await
                        .get(&addr, 0)
                        .ok()
                        .unwrap_or(0) != 0;
                    if currently_replaying {
                        log::info!(
                            "idle-monitor: IPv6 {} traffic resumed, disabling replay",
                            std::net::Ipv6Addr::from(addr)
                        );
                        let _ = replaylist_v6.lock().await.remove(&addr);
                    }
                }
            }
        }
    });
}
