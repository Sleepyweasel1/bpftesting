#![no_std]
#![no_main]

use aya_ebpf::{bindings::tcx_action_base::*, helpers::bpf_ktime_get_ns, macros::{classifier, map}, maps::HashMap, programs::TcContext};
use aya_log_ebpf::info;
use network_types::{eth::{EthHdr, EtherType}, ip::Ipv4Hdr};


#[map]
static BLOCKLIST: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

#[classifier]
pub fn hold_packet(ctx: TcContext) -> i32 {
    match try_hold_packet(ctx) {
        Ok(ret) => ret,
        Err(_) => TCX_NEXT,
    }
}

fn block_ip(address: u32) -> bool {
    unsafe { BLOCKLIST.get(&address).is_some() }
}

fn try_hold_packet(ctx: TcContext) -> Result<i32, ()> {
    // info!(&ctx, "received a packet");
    let timestamp = unsafe{bpf_ktime_get_ns()};
    // Ok(TC_ACT_PIPE)
        let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    match ethhdr.ether_type() {
        Ok(EtherType::Ipv4) => {}
        _ => return Ok(TCX_NEXT),
    }

    let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
    let destination = u32::from_be_bytes(ipv4hdr.dst_addr);
    let source = u32::from_be_bytes(ipv4hdr.src_addr);
    let action = if block_ip(destination) {
        info!(&ctx, "DEST {:i}, SRC {:i}, TS {}", destination, source, timestamp);

        TCX_DROP
    } else {
        TCX_NEXT
    };
    // info!(&ctx, "DEST {:i}, SRC {:i}, ACTION {}, TS {}", destination, source, action, timestamp);

    Ok(action)
    
}
// fn try_tc_egress(ctx: TcContext) -> Result<i32, ()> {
//     let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;
//     match ethhdr.ether_type() {
//         Ok(EtherType::Ipv4) => {}
//         _ => return Ok(TC_ACT_PIPE),
//     }

//     let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
//     let destination = u32::from_be_bytes(ipv4hdr.dst_addr);

//     let action = if block_ip(destination) {
//         TC_ACT_SHOT
//     } else {
//         TC_ACT_PIPE
//     };

//     info!(&ctx, "DEST {:i}, ACTION {}", destination, action);

//     Ok(action)
// }
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
