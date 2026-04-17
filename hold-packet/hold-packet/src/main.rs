use std::{net::Ipv4Addr, sync::Arc};

use aya::{
    maps::HashMap,
    programs::{LinkOrder, SchedClassifier, TcAttachType, tc},
};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::sync::Mutex;
use tonic::transport::Server;

use grpc::BlocklistServer;
use holdpacket::blocklist_service_server::BlocklistServiceServer;

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
    let Opt { iface, grpc_addr } = opt;
    // error adding clsact to the interface if it is already added is harmless
    // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.
    // let _ = tc::qdisc_add_clsact(&iface);
    let program: &mut SchedClassifier = ebpf.program_mut("hold_packet").unwrap().try_into()?;
    program.load()?;
    program.attach_with_options(&iface, TcAttachType::Ingress, tc::TcAttachOptions::TcxOrder(LinkOrder::first()))?;

    // Take ownership of the BLOCKLIST map so it can be shared with the gRPC service.
    let blocklist_map = ebpf
        .take_map("BLOCKLIST")
        .expect("BLOCKLIST map not found");
    let blocklist: HashMap<_, u32, u32> = HashMap::try_from(blocklist_map)?;

    let block_addr: u32 = Ipv4Addr::new(142, 250, 9, 139).into();

    let shared_blocklist = Arc::new(Mutex::new(blocklist));

    // Insert the initial hardcoded block rule.
    shared_blocklist.lock().await.insert(block_addr, 0, 0)?;

    // Start the gRPC control-plane server.
    let grpc_addr = grpc_addr.parse()?;
    let svc = BlocklistServiceServer::new(BlocklistServer {
        blocklist: shared_blocklist,
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
