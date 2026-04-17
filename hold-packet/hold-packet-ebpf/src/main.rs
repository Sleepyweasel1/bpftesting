#![no_std]
#![no_main]

use aya_ebpf::{bindings::tcx_action_base::*, helpers::bpf_ktime_get_ns, macros::{classifier, map}, maps::HashMap, programs::TcContext};
use aya_log_ebpf::info;
use network_types::{eth::{EthHdr, EtherType}, ip::Ipv4Hdr, ip::Ipv6Hdr};


#[map]
static CAPTURELISTV4: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);
#[map]
static CAPTURELISTV6: HashMap<u128, u32> = HashMap::with_max_entries(1024, 0);


#[classifier]
pub fn hold_packet(ctx: TcContext) -> i32 {
    match try_hold_packet(ctx) {
        Ok(ret) => ret,
        Err(_) => TCX_NEXT,
    }
}
fn is_replayed(ctx: &TcContext) -> bool {
    unsafe { (*ctx.skb.skb).mark  == 0xCAFE }
}



fn capture_ipv6(address: u128) -> bool {
    unsafe { CAPTURELISTV6.get(&address).is_some() }
}
fn capture_ipv4(address: u32) -> bool {
    unsafe { CAPTURELISTV4.get(&address).is_some() }
}
fn try_hold_packet(ctx: TcContext) -> Result<i32, ()> {
    if is_replayed(&ctx) {
        return Ok(TCX_NEXT); // let replayed packets pass through
    }
    // info!(&ctx, "received a packet");
    let timestamp = unsafe{bpf_ktime_get_ns()};
    // Ok(TC_ACT_PIPE)
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    match ethhdr.ether_type() {
        Ok(EtherType::Ipv4) => {
            let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
            let destination = u32::from_be_bytes(ipv4hdr.dst_addr);
            let source = u32::from_be_bytes(ipv4hdr.src_addr);
            if capture_ipv4(destination) {
                info!(&ctx, "DEST {:i}, SRC {:i}, TS {}", destination, source, timestamp);
                // return Ok(TCX_DROP);
            }
        }
        Ok(EtherType::Ipv6) => {
            let ipv6hdr: Ipv6Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
            let destination = u128::from_be_bytes(ipv6hdr.dst_addr);
            if capture_ipv6(destination) {
                info!(&ctx, "IPv6 destination to capture, TS {}", timestamp);
                // return Ok(TCX_DROP);
            }
        }
        _ => return Ok(TCX_NEXT),
    }

    Ok(TCX_NEXT)
    // info!(&ctx, "DEST {:i}, SRC {:i}, ACTION {}, TS {}", destination, source, action, timestamp);

    
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
