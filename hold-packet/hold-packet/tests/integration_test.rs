use aya::{
    maps::HashMap,
    programs::{LinkOrder, SchedClassifier, TcAttachType, tc},
};
use hold_packet_common::{StateEntry, CaptureMode};
use std::{
    fs,
    io::{BufRead, BufReader},
    process::{Child, Command, Stdio},
    sync::Arc,
    sync::mpsc::{self, Receiver},
    time::Instant,
};
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex;
use tokio::time::{Duration, sleep};

pub mod holdpacket {
    tonic::include_proto!("holdpacket");
}

use holdpacket::{
    AddRuleRequest,
    ReplayRuleRequest,
    capturelist_service_client::CapturelistServiceClient,
};

struct VethFixture {
    iface_ingress: String,
    iface_peer: String,
}

struct TapFixture {
    name: String,
    device: Arc<Mutex<tun::AsyncDevice>>,
}

impl TapFixture {
    fn new() -> Self {
        let name = format!("tap{}", std::process::id() % 10_000);
        // Clean up any stale TAP device from a previous run
        let _ = Command::new("ip")
            .args(["tuntap", "del", "dev", &name, "mode", "tap"])
            .output();
        
        let mut config = tun::Configuration::default();
        config.tun_name(&name).layer(tun::Layer::L2).up();
        let device = tun::create_as_async(&config)
            .unwrap_or_else(|e| panic!("failed to create TAP device {name}: {e}"));

        Self {
            name,
            device: Arc::new(Mutex::new(device)),
        }
    }
    
    fn ifindex(&self) -> u32 {
        fs::read_to_string(format!("/sys/class/net/{}/ifindex", self.name))
            .unwrap_or_else(|e| panic!("failed to read TAP ifindex: {e}"))
            .trim()
            .parse::<u32>()
            .unwrap_or_else(|e| panic!("failed to parse TAP ifindex: {e}"))
    }
}

impl Drop for TapFixture {
    fn drop(&mut self) {
        let _ = Command::new("ip")
            .args(["tuntap", "del", "dev", &self.name, "mode", "tap"])
            .output();
    }
}

fn run_cmd(args: &[&str]) {
    let output = Command::new(args[0])
        .args(&args[1..])
        .output()
        .unwrap_or_else(|e| panic!("failed to run command {:?}: {e}", args));
    assert!(
        output.status.success(),
        "command {:?} failed with status {:?}\nstdout: {}\nstderr: {}",
        args,
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

impl VethFixture {
    fn new() -> Self {
        let suffix = std::process::id() % 10_000;
        let iface_ingress = format!("hp{suffix}a");
        let iface_peer = format!("hp{suffix}b");

        // Clean up any stale interface from a previous interrupted run.
        let _ = Command::new("ip")
            .args(["link", "del", iface_ingress.as_str()])
            .output();

        run_cmd(&[
            "ip",
            "link",
            "add",
            iface_ingress.as_str(),
            "type",
            "veth",
            "peer",
            "name",
            iface_peer.as_str(),
        ]);
        run_cmd(&[
            "ip",
            "addr",
            "add",
            "10.200.1.1/24",
            "dev",
            iface_ingress.as_str(),
        ]);
        run_cmd(&[
            "ip",
            "addr",
            "add",
            "10.200.1.2/24",
            "dev",
            iface_peer.as_str(),
        ]);
        run_cmd(&["ip", "link", "set", "dev", iface_ingress.as_str(), "up"]);
        run_cmd(&["ip", "link", "set", "dev", iface_peer.as_str(), "up"]);

        Self {
            iface_ingress,
            iface_peer,
        }
    }
}

impl Drop for VethFixture {
    fn drop(&mut self) {
        // tcx cleanup is automatic, no manual qdisc removal needed
        let _ = Command::new("ip")
            .args(["link", "del", self.iface_ingress.as_str()])
            .output();
    }
}

fn read_ifindex(iface: &str) -> i32 {
    fs::read_to_string(format!("/sys/class/net/{iface}/ifindex"))
        .unwrap_or_else(|e| panic!("failed to read ifindex for {iface}: {e}"))
        .trim()
        .parse::<i32>()
        .unwrap_or_else(|e| panic!("failed to parse ifindex for {iface}: {e}"))
}

fn parse_mac(mac: &str) -> [u8; 6] {
    let mut out = [0u8; 6];
    let parts: Vec<&str> = mac.split(':').collect();
    assert_eq!(parts.len(), 6, "invalid MAC address format: {mac}");
    for (idx, part) in parts.iter().enumerate() {
        out[idx] = u8::from_str_radix(part, 16)
            .unwrap_or_else(|e| panic!("invalid MAC component '{part}' in {mac}: {e}"));
    }
    out
}

fn read_mac(iface: &str) -> [u8; 6] {
    let mac = fs::read_to_string(format!("/sys/class/net/{iface}/address"))
        .unwrap_or_else(|e| panic!("failed to read MAC address for {iface}: {e}"));
    parse_mac(mac.trim())
}

fn parse_ipv4_addrs_from_frame(frame: &[u8]) -> Option<([u8; 4], [u8; 4])> {
    const IPV4_ETHERTYPE: [u8; 2] = 0x0800u16.to_be_bytes();

    if frame.len() >= 34 && frame[12..14] == IPV4_ETHERTYPE {
        return Some((frame[26..30].try_into().ok()?, frame[30..34].try_into().ok()?));
    }

    if frame.len() >= 38 && frame[16..18] == IPV4_ETHERTYPE {
        return Some((frame[30..34].try_into().ok()?, frame[34..38].try_into().ok()?));
    }

    if frame.len() >= 20 && (frame[0] >> 4) == 4 {
        return Some((frame[12..16].try_into().ok()?, frame[16..20].try_into().ok()?));
    }

    if frame.len() >= 24 && (frame[4] >> 4) == 4 {
        return Some((frame[16..20].try_into().ok()?, frame[20..24].try_into().ok()?));
    }

    None
}

fn ipv4_header_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in header.chunks_exact(2) {
        sum = sum.wrapping_add(u16::from_be_bytes([chunk[0], chunk[1]]) as u32);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn send_test_ipv4_frame_with_mark(
    iface: &str,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    mark: Option<u32>,
) {
    let mut frame = [0u8; 34];

    // Ethernet header
    frame[0..6].copy_from_slice(&dst_mac);
    frame[6..12].copy_from_slice(&src_mac);
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());

    // IPv4 header
    let ip = &mut frame[14..];
    ip[0] = 0x45; // version=4, IHL=5
    ip[2..4].copy_from_slice(&20u16.to_be_bytes()); // total length
    ip[8] = 64; // TTL
    ip[9] = 17; // UDP protocol
    ip[12..16].copy_from_slice(&src_ip);
    ip[16..20].copy_from_slice(&dst_ip);
    let checksum = ipv4_header_checksum(ip);
    ip[10..12].copy_from_slice(&checksum.to_be_bytes());

    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            i32::from((libc::ETH_P_IP as u16).to_be()),
        )
    };
    assert!(fd >= 0, "socket(AF_PACKET) failed: {}", std::io::Error::last_os_error());

    if let Some(mark) = mark {
        let set_mark_ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_MARK,
                &mark as *const u32 as *const libc::c_void,
                std::mem::size_of::<u32>() as libc::socklen_t,
            )
        };
        assert_eq!(
            set_mark_ret,
            0,
            "setsockopt(SO_MARK) failed: {}",
            std::io::Error::last_os_error()
        );
    }

    let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_protocol = (libc::ETH_P_IP as u16).to_be();
    addr.sll_ifindex = read_ifindex(iface);
    addr.sll_halen = 6;
    addr.sll_addr[..6].copy_from_slice(&dst_mac);

    let sent = unsafe {
        libc::sendto(
            fd,
            frame.as_ptr() as *const libc::c_void,
            frame.len(),
            0,
            &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    let close_ret = unsafe { libc::close(fd) };
    assert_eq!(close_ret, 0, "close(socket) failed: {}", std::io::Error::last_os_error());
    assert_eq!(
        sent,
        frame.len() as isize,
        "sendto() failed: {}",
        std::io::Error::last_os_error()
    );
}

fn send_test_ipv4_frame(iface: &str, src_mac: [u8; 6], dst_mac: [u8; 6], src_ip: [u8; 4], dst_ip: [u8; 4]) {
    send_test_ipv4_frame_with_mark(iface, src_mac, dst_mac, src_ip, dst_ip, None);
}

struct ChildGuard {
    child: Child,
}

impl ChildGuard {
    fn spawn_hold_packet(iface: &str, grpc_addr: &str) -> Self {
        let bin_path = env!("CARGO_BIN_EXE_hold-packet");
        let child = Command::new(bin_path)
            .args([
                "--iface",
                iface,
                "--grpc-addr",
                grpc_addr,
                "--idle-timeout-secs",
                "0",
            ])
            .env("RUST_LOG", "info")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("failed to spawn hold-packet userspace binary: {e}"));

        Self { child }
    }

    fn try_wait(&mut self) -> Option<std::process::ExitStatus> {
        self.child
            .try_wait()
            .unwrap_or_else(|e| panic!("failed to query child status: {e}"))
    }

    fn take_stderr(&mut self) -> std::process::ChildStderr {
        self.child
            .stderr
            .take()
            .expect("failed to capture userspace stderr")
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.try_wait().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn spawn_line_reader(stderr: std::process::ChildStderr) -> Receiver<String> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines() {
            if let Ok(line) = line {
                let _ = tx.send(line);
            }
        }
    });
    rx
}

async fn wait_for_grpc(grpc_endpoint: &str, timeout: Duration) {
    let start = Instant::now();
    loop {
        if CapturelistServiceClient::connect(grpc_endpoint.to_string())
            .await
            .is_ok()
        {
            return;
        }
        if start.elapsed() > timeout {
            panic!("gRPC server did not become ready at {grpc_endpoint}");
        }
        sleep(Duration::from_millis(100)).await;
    }
}

fn parse_staged_id(line: &str) -> Option<u64> {
    let marker = "Staged packet with ID ";
    let idx = line.find(marker)?;
    line[idx + marker.len()..].trim().parse::<u64>().ok()
}

#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore = "eBPF integration tests require Linux")]
async fn test_hold_packet_ebpf() {
    // Root is required for tc, link management, and loading eBPF programs.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("Skipping test_hold_packet_ebpf: requires root");
        return;
    }

    let fixture = VethFixture::new();

    // Load the compiled eBPF program
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/hold-packet"
    ))).expect("Failed to load eBPF object file");

    let program: &mut SchedClassifier = ebpf
        .program_mut("hold_packet")
        .expect("Program not found")
        .try_into()
        .expect("Program is not a SchedClassifier");

    program.load().expect("Failed to load program into kernel");
    program
        .attach_with_options(&fixture.iface_ingress, TcAttachType::Ingress, tc::TcAttachOptions::TcxOrder(LinkOrder::first()))
        .expect("Failed to attach tc ingress classifier");

    // Insert test state into STATEV4 map
    let statelistv4_map = ebpf
        .take_map("STATEV4")
        .expect("STATEV4 map not found");
    let mut statelistv4: HashMap<_, u32, StateEntry> = HashMap::try_from(statelistv4_map).unwrap();

    let test_ip: u32 = u32::from_be_bytes([10, 200, 1, 1]);
    let test_entry = StateEntry::default();
    statelistv4.insert(test_ip, test_entry, 0).expect("Failed to insert map entry");

    // Send a crafted L2/L3 frame from the peer end so it arrives on ingress.
    let src_mac = read_mac(&fixture.iface_peer);
    let dst_mac = read_mac(&fixture.iface_ingress);
    send_test_ipv4_frame(
        &fixture.iface_peer,
        src_mac,
        dst_mac,
        [10, 200, 1, 2],
        [10, 200, 1, 1],
    );

    // Verify that last_seen_ns was updated by the eBPF program.
    for attempt in 0..40 {
        if let Ok(entry) = statelistv4.get(&test_ip, 0) {
            if entry.last_seen_ns > 0 {
                return; // Test passed
            }
        }
        sleep(Duration::from_millis(50)).await;
        if attempt == 39 {
            assert!(false, "last_seen_ns was not updated by eBPF program");
        }
    }
}

#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore = "eBPF integration tests require Linux")]
async fn test_hold_packet_replay_e2e() {
    // Root is required for tc, link management, TAP device creation, and loading eBPF programs.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("Skipping test_hold_packet_replay_e2e: requires root");
        return;
    }

    let veth_fixture = VethFixture::new();
    let tap_fixture = TapFixture::new();
    let tap_ifindex = tap_fixture.ifindex();

    // Load the compiled eBPF program
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/hold-packet"
    ))).expect("Failed to load eBPF object file");

    // Set the TAP ifindex in the eBPF map before attaching
    let tap_ifindex_arr = ebpf
        .take_map("TAP_IFINDEX")
        .expect("TAP_IFINDEX map not found");
    let mut tap_ifindex_map: aya::maps::Array<_, u32> = aya::maps::Array::try_from(tap_ifindex_arr).unwrap();
    tap_ifindex_map.set(0, tap_ifindex, 0).expect("Failed to set TAP ifindex");

    let program: &mut SchedClassifier = ebpf
        .program_mut("hold_packet")
        .expect("Program not found")
        .try_into()
        .expect("Program is not a SchedClassifier");

    program.load().expect("Failed to load program into kernel");
    program
        .attach_with_options(&veth_fixture.iface_ingress, TcAttachType::Ingress, tc::TcAttachOptions::TcxOrder(LinkOrder::first()))
        .expect("Failed to attach tc ingress classifier");

    // Get access to the STATEV4 map
    let statelistv4_map = ebpf
        .take_map("STATEV4")
        .expect("STATEV4 map not found");
    let mut statelistv4: HashMap<_, u32, StateEntry> = HashMap::try_from(statelistv4_map).unwrap();

    let test_ip: u32 = u32::from_be_bytes([10, 200, 1, 1]);
    
    // === Test Case 1: Packet with capture but no replay (should not redirect) ===
    let mut test_entry = StateEntry::default();
    test_entry.mode = CaptureMode::PassThrough; // No replay
    statelistv4.insert(test_ip, test_entry, 0).expect("Failed to insert map entry");

    let src_mac = read_mac(&veth_fixture.iface_peer);
    let dst_mac = read_mac(&veth_fixture.iface_ingress);
    send_test_ipv4_frame(
        &veth_fixture.iface_peer,
        src_mac,
        dst_mac,
        [10, 200, 1, 2],
        [10, 200, 1, 1],
    );

    // Wait for eBPF to process the packet
    sleep(Duration::from_millis(100)).await;

    // Verify last_seen_ns was updated (packet was captured)
    let entry = statelistv4.get(&test_ip, 0).expect("Entry missing from map");
    assert!(entry.last_seen_ns > 0, "Packet should be captured but replay disabled");

    // === Test Case 2: Packet with replay enabled (should redirect to TAP) ===
    let initial_ts = entry.last_seen_ns;
    let mut test_entry = StateEntry::default();
    test_entry.mode = CaptureMode::Hold; // Enable replay
    statelistv4.insert(test_ip, test_entry, 0).expect("Failed to update map entry");

    let tap_read = Arc::clone(&tap_fixture.device);
    let read_task = tokio::spawn(async move {
        let mut device = tap_read.lock().await;
        loop {
            let mut buf = [0u8; 2048];
            let n = device
                .read(&mut buf)
                .await
                .expect("Failed to read redirected frame from TAP device");
            let packet = buf[..n].to_vec();

            if let Some((captured_src_ip, captured_dst_ip)) = parse_ipv4_addrs_from_frame(&packet) {
                if captured_src_ip == [10, 200, 1, 2] && captured_dst_ip == [10, 200, 1, 1] {
                    return packet;
                }
            }
        }
    });

    // Send a packet destined for the test IP with replay enabled
    send_test_ipv4_frame(
        &veth_fixture.iface_peer,
        src_mac,
        dst_mac,
        [10, 200, 1, 2],
        [10, 200, 1, 1],
    );

    // Wait for packet to be redirected to TAP
    let packet_data = match tokio::time::timeout(Duration::from_secs(2), read_task).await {
        Ok(join_result) => join_result.expect("TAP reader task panicked"),
        Err(_) => panic!("Timed out waiting for redirected IPv4 packet on TAP device"),
    };
    let captured_len = packet_data.len();
    assert!(
        captured_len >= 34,
        "Captured packet from TAP is too small: {} bytes",
        captured_len
    );

    let (captured_src_ip, captured_dst_ip) = parse_ipv4_addrs_from_frame(&packet_data)
        .unwrap_or_else(|| panic!("Captured packet did not contain a recognizable IPv4 frame: {:02x?}", packet_data));

    assert_eq!(
        captured_src_ip, [10, 200, 1, 2],
        "Captured packet has incorrect source IP"
    );
    assert_eq!(
        captured_dst_ip, [10, 200, 1, 1],
        "Captured packet has incorrect destination IP"
    );

    // === Test Case 3: Verify replay flag persists and works consistently ===
    let entry = statelistv4.get(&test_ip, 0).expect("Entry missing from map");
    assert_eq!(entry.mode, CaptureMode::Hold, "Capture mode should remain Hold");
    assert!(
        entry.last_seen_ns > initial_ts,
        "last_seen_ns should be updated for redirected packet"
    );
}

#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore = "eBPF integration tests require Linux")]
async fn test_hold_packet_redirects_packets_marked_cafe_in_option_a() {
    // Root is required for tc, link management, TAP device creation, and loading eBPF programs.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("Skipping test_hold_packet_redirects_packets_marked_cafe_in_option_a: requires root");
        return;
    }

    let veth_fixture = VethFixture::new();
    let tap_fixture = TapFixture::new();
    let tap_ifindex = tap_fixture.ifindex();

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/hold-packet"
    )))
    .expect("Failed to load eBPF object file");

    let tap_ifindex_arr = ebpf
        .take_map("TAP_IFINDEX")
        .expect("TAP_IFINDEX map not found");
    let mut tap_ifindex_map: aya::maps::Array<_, u32> =
        aya::maps::Array::try_from(tap_ifindex_arr).unwrap();
    tap_ifindex_map
        .set(0, tap_ifindex, 0)
        .expect("Failed to set TAP ifindex");

    let program: &mut SchedClassifier = ebpf
        .program_mut("hold_packet")
        .expect("Program not found")
        .try_into()
        .expect("Program is not a SchedClassifier");

    program.load().expect("Failed to load program into kernel");
    program
        .attach_with_options(
            &veth_fixture.iface_ingress,
            TcAttachType::Ingress,
            tc::TcAttachOptions::TcxOrder(LinkOrder::first()),
        )
        .expect("Failed to attach tc ingress classifier");

    let statelistv4_map = ebpf.take_map("STATEV4").expect("STATEV4 map not found");
    let mut statelistv4: HashMap<_, u32, StateEntry> = HashMap::try_from(statelistv4_map).unwrap();

    let test_ip: u32 = u32::from_be_bytes([10, 200, 1, 1]);
    let mut test_entry = StateEntry::default();
    test_entry.mode = CaptureMode::Hold;
    statelistv4
        .insert(test_ip, test_entry, 0)
        .expect("Failed to insert replay-enabled map entry");

    let src_mac = read_mac(&veth_fixture.iface_peer);
    let dst_mac = read_mac(&veth_fixture.iface_ingress);

    let tap_read = Arc::clone(&tap_fixture.device);
    let read_task = tokio::spawn(async move {
        let mut device = tap_read.lock().await;
        loop {
            let mut buf = [0u8; 2048];
            let n = device
                .read(&mut buf)
                .await
                .expect("Failed to read redirected frame from TAP device");
            let packet = buf[..n].to_vec();

            if let Some((captured_src_ip, captured_dst_ip)) = parse_ipv4_addrs_from_frame(&packet) {
                if captured_src_ip == [10, 200, 1, 2] && captured_dst_ip == [10, 200, 1, 1] {
                    return packet;
                }
            }
        }
    });

    // Option A invariant: packet mark is ignored by classifier behavior.
    send_test_ipv4_frame_with_mark(
        &veth_fixture.iface_peer,
        src_mac,
        dst_mac,
        [10, 200, 1, 2],
        [10, 200, 1, 1],
        Some(0xCAFE),
    );

    let packet_data = match tokio::time::timeout(Duration::from_secs(2), read_task).await {
        Ok(join_result) => join_result.expect("TAP reader task panicked"),
        Err(_) => panic!("Timed out waiting for redirected IPv4 packet on TAP device"),
    };

    assert!(
        packet_data.len() >= 34,
        "Captured packet from TAP is too small: {} bytes",
        packet_data.len()
    );
    let (captured_src_ip, captured_dst_ip) = parse_ipv4_addrs_from_frame(&packet_data)
        .unwrap_or_else(|| panic!("Captured packet did not contain a recognizable IPv4 frame: {:02x?}", packet_data));
    assert_eq!(captured_src_ip, [10, 200, 1, 2], "Captured packet has incorrect source IP");
    assert_eq!(captured_dst_ip, [10, 200, 1, 1], "Captured packet has incorrect destination IP");
}

#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore = "eBPF integration tests require Linux")]
async fn test_userspace_replay_blackbox_e2e() {
    // Root is required for tc attachment, link management, and the TAP/replay path.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("Skipping test_userspace_replay_blackbox_e2e: requires root");
        return;
    }

    let fixture = VethFixture::new();

    let bind = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("failed to reserve ephemeral gRPC port");
    let grpc_port = bind.local_addr().expect("failed to read local addr").port();
    drop(bind);

    let grpc_addr = format!("127.0.0.1:{grpc_port}");
    let grpc_endpoint = format!("http://{grpc_addr}");

    let mut userspace = ChildGuard::spawn_hold_packet(&fixture.iface_ingress, &grpc_addr);
    let stderr_rx = spawn_line_reader(userspace.take_stderr());

    wait_for_grpc(&grpc_endpoint, Duration::from_secs(8)).await;
    let mut client = CapturelistServiceClient::connect(grpc_endpoint.clone())
        .await
        .expect("failed to connect to userspace gRPC server");

    let ip = "10.200.1.1".to_string();
    client
        .add_rule(AddRuleRequest { ip: ip.clone() })
        .await
        .expect("add_rule RPC failed");

    let src_mac = read_mac(&fixture.iface_peer);
    let dst_mac = read_mac(&fixture.iface_ingress);

    // First packet updates last_seen_ns while replay is still disabled.
    send_test_ipv4_frame(
        &fixture.iface_peer,
        src_mac,
        dst_mac,
        [10, 200, 1, 2],
        [10, 200, 1, 1],
    );

    // Idle monitor ticks every 30s; with timeout=0, next tick flips replay on.
    sleep(Duration::from_secs(31)).await;

    // Next packet should be redirected to tap1 and staged by userspace.
    send_test_ipv4_frame(
        &fixture.iface_peer,
        src_mac,
        dst_mac,
        [10, 200, 1, 2],
        [10, 200, 1, 1],
    );

    let stage_deadline = Instant::now() + Duration::from_secs(5);
    let staged_id = loop {
        if let Some(status) = userspace.try_wait() {
            panic!("userspace binary exited unexpectedly: {status}");
        }

        match stderr_rx.recv_timeout(std::time::Duration::from_millis(200)) {
            Ok(line) => {
                if let Some(id) = parse_staged_id(&line) {
                    break id;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if Instant::now() > stage_deadline {
                    panic!("timed out waiting for staged packet log line");
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                panic!("userspace stderr stream disconnected before staging");
            }
        }
    };

    client
        .replay_rule(ReplayRuleRequest { id: staged_id })
        .await
        .expect("replay_rule should succeed for staged packet id");

    // Replaying the same packet a second time must fail because it is consumed.
    let second = client.replay_rule(ReplayRuleRequest { id: staged_id }).await;
    assert!(second.is_err(), "second replay call should fail for consumed id");
}
