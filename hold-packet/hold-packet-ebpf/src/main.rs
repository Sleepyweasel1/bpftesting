#![no_std]
#![no_main]

use core::u128;

use aya_ebpf::{EbpfContext, bindings::tcx_action_base::*, helpers::{bpf_ktime_get_ns, generated::{bpf_clone_redirect, bpf_redirect}}, macros::{classifier, map}, maps::{Array, HashMap}, programs::TcContext};
use aya_log_ebpf::info;
use hold_packet_common::StateEntry;
use network_types::{eth::{EthHdr, EtherType}, ip::Ipv4Hdr, ip::Ipv6Hdr};


#[map]
static STATEV4: HashMap<u32, StateEntry> = HashMap::with_max_entries(1024, 0);
#[map]
static STATEV6: HashMap<u128, StateEntry> = HashMap::with_max_entries(1024, 0);
#[map]
static TAP_IFINDEX: Array<u32> = Array::with_max_entries(1, 0);

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

fn redirect_to_tap() -> i32 {
    if let Some(ifindex) = TAP_IFINDEX.get(0) {
        if *ifindex != 0 {
            // bpf_redirect returns TC_ACT_REDIRECT (7) — packet is consumed
            return unsafe { bpf_redirect(*ifindex, 0) as i32 };
        }
    }
    TCX_NEXT // tap not configured yet, let it through
}

fn replay_v6 (address: u128) -> bool {
    unsafe { 
        if let Some(replay) = STATEV6.get(&address) {
            return replay.replay != 0;
        }
    }
    false
}
fn replay_v4 (address: u32) -> bool {
    unsafe { 
        if let Some(replay) = STATEV4.get(&address) {
            return replay.replay != 0;
        }
    }
    false
}

fn capture_ipv6(address: u128) -> bool {
    unsafe { STATEV6.get(&address).is_some() }
}
fn capture_ipv4(address: u32) -> bool {
    unsafe { STATEV4.get(&address).is_some() }
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
                if let Some(ts) =  STATEV4.get_ptr_mut(&destination) {
                    unsafe { (*ts).last_seen_ns = bpf_ktime_get_ns() };
                }
                if replay_v4(destination) {
                    return Ok(redirect_to_tap());
                }
            }
        }
        Ok(EtherType::Ipv6) => {
            let ipv6hdr: Ipv6Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
            let destination = u128::from_be_bytes(ipv6hdr.dst_addr);
            if capture_ipv6(destination) {
                info!(&ctx, "IPv6 destination to capture, TS {}", timestamp);
                if let Some(ts) =  STATEV6.get_ptr_mut(&destination) {
                    unsafe { (*ts).last_seen_ns = bpf_ktime_get_ns() };
                }
                if replay_v6(destination) {
                    return Ok(redirect_to_tap());
                }
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
