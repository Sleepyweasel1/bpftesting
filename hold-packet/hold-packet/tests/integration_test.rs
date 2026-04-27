use aya::{
    maps::{HashMap, MapData},
    programs::{SchedClassifier, TcAttachType, tc},
};
use hold_packet_common::StateEntry;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
};

#[tokio::test]
#[cfg_attr(not(target_os = "linux"), ignore = "eBPF integration tests require Linux")]
async fn test_hold_packet_ebpf() {
    // Note: This requires root privileges to run on Linux.
    
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

    // Insert test state into STATEV4 map
    let statelistv4_map = ebpf
        .take_map("STATEV4")
        .expect("STATEV4 map not found");
    let mut statelistv4: HashMap<MapData, u32> = HashMap::try_from(statelistv4_map).unwrap();

    let test_ip: u32 = u32::from_be_bytes([192, 168, 1, 100]);
    let test_entry = StateEntry {
        replay: 0,
        last_seen_ns: 0,
        pad: 0,
    };
    statelistv4.insert(test_ip, test_entry, 0).expect("Failed to insert map entry");

    // Construct a dummy IPv4 packet directed to test_ip
    let mut packet = vec![0u8; EthHdr::LEN + Ipv4Hdr::LEN];
    
    // Safety: we zero-initialized the slice, so it's safe to cast to headers
    unsafe {
        let eth = packet.as_mut_ptr() as *mut EthHdr;
        (*eth).ether_type = EtherType::Ipv4.into();
        
        let ipv4 = packet.as_mut_ptr().add(EthHdr::LEN) as *mut Ipv4Hdr;
        (*ipv4).dst_addr = test_ip.to_be_bytes();
    }

    // Use test run API
    let res = program.test(&packet, &[]).expect("Failed to run test");
    
    // 2 is TCX_NEXT (defined in aya_ebpf bindings, typically 2 or equivalent for Tcx)
    // Actually, Tcx NEXT is usually 2. 
    // We expect it to pass without error.
    assert_eq!(res.retval, 2, "Expected TCX_NEXT (2)");

    // Verify that last_seen_ns was updated by the eBPF program
    let updated_entry = statelistv4.get(&test_ip, 0).expect("Entry missing from map");
    assert!(updated_entry.last_seen_ns > 0, "last_seen_ns was not updated by eBPF program");
}
