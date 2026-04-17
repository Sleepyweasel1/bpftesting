use std::collections::HashMap;
use std::ffi::CString;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::Mutex;
use tokio::time::{Duration, Instant};
use tun::Configuration;

/// Staged packets are discarded after this duration. 120 s covers the Linux
/// TCP SYN retransmit window (~127 s) with a small margin; any TCP peer whose
/// SYN we held will have given up by the time we'd exceed this.
pub const STAGED_TTL: Duration = Duration::from_secs(120);

/// A raw L2 frame held in the staging area awaiting an operator decision.
pub struct StagedPacket {
    pub data: Vec<u8>,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub len: usize,
    pub staged_at: Instant,
}

pub struct Replayer {
    tap_reader: Arc<Mutex<ReadHalf<tun::AsyncDevice>>>,
    tap_writer: Arc<Mutex<WriteHalf<tun::AsyncDevice>>>,
    tap_ifindex: u32,
    pub next_id: Arc<AtomicU64>,
    pub staged: Arc<Mutex<HashMap<u64, StagedPacket>>>,
}

impl Replayer {
    pub fn new(tap_name: &str) -> anyhow::Result<Self> {
        let mut config = Configuration::default();
        config.tun_name(tap_name).layer(tun::Layer::L2).up();
        let tap = tun::create_as_async(&config)?;

        let tap_ifindex = unsafe {
            let name = CString::new(tap_name)?;
            libc::if_nametoindex(name.as_ptr())
        };

        let (reader, writer) = tokio::io::split(tap);

        Ok(Self {
            tap_reader: Arc::new(Mutex::new(reader)),
            tap_writer: Arc::new(Mutex::new(writer)),
            tap_ifindex,
            next_id: Arc::new(AtomicU64::new(1)),
            staged: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub fn tap_ifindex(&self) -> u32 {
        self.tap_ifindex
    }

    /// Reads one L2 frame from the TAP device, parses the source/destination
    /// IPs from the IP header, and stages the frame under a new unique ID.
    /// Returns the assigned ID so the caller can notify the operator.
    pub async fn read_and_stage(&self) -> std::io::Result<u64> {
        let mut buf = [0u8; 65536];
        let n = self.tap_reader.lock().await.read(&mut buf).await?;

        let (src_ip, dst_ip) = parse_ip_addrs(&buf[..n]);
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);

        self.staged.lock().await.insert(
            id,
            StagedPacket {
                data: buf[..n].to_vec(),
                src_ip,
                dst_ip,
                len: n,
                staged_at: Instant::now(),
            },
        );

        Ok(id)
    }

    /// Replays the staged packet with the given ID onto the replay interface
    /// and removes it from the staging map.
    pub async fn replay_staged(&self, id: u64) -> std::io::Result<()> {
        let packet = self
            .staged
            .lock()
            .await
            .remove(&id)
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "packet id not found")
            })?;

        self.send_packet(&packet.data).await
    }

    /// Discards the staged packet with the given ID without replaying it.
    pub async fn drop_staged(&self, id: u64) -> std::io::Result<()> {
        self.staged
            .lock()
            .await
            .remove(&id)
            .map(|_| ())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "packet id not found")
            })
    }

    /// Spawns a background task that removes expired staged packets every 30 s.
    /// Call once after construction; the task holds an `Arc` clone of the map
    /// and will keep running until the process exits.
    pub fn spawn_pruner(&self) {
        let staged = Arc::clone(&self.staged);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                interval.tick().await;
                let now = Instant::now();
                staged
                    .lock()
                    .await
                    .retain(|_, p| now.duration_since(p.staged_at) < STAGED_TTL);
            }
        });
    }

    /// Writes the frame back to the TAP fd so the kernel processes it as a
    /// received frame on the TAP interface (RX path → routing → DNAT → pod).
    /// The eBPF TC filter lives on eth0 ingress, not the TAP, so there is no
    /// recapture loop.
    async fn send_packet(&self, data: &[u8]) -> std::io::Result<()> {
        self.tap_writer.lock().await.write_all(data).await
    }
}

/// Parses source and destination IP addresses from an Ethernet frame.
/// Returns `UNSPECIFIED` for both if the frame is too short or not IPv4/IPv6.
fn parse_ip_addrs(frame: &[u8]) -> (IpAddr, IpAddr) {
    use std::net::{Ipv4Addr, Ipv6Addr};

    const ETH_HDR: usize = 14;
    const IPV4_ET: u16 = 0x0800;
    const IPV6_ET: u16 = 0x86DD;

    if frame.len() < ETH_HDR + 2 {
        return (IpAddr::V4(Ipv4Addr::UNSPECIFIED), IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    }

    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    match ethertype {
        IPV4_ET if frame.len() >= ETH_HDR + 20 => {
            let src = Ipv4Addr::from([
                frame[ETH_HDR + 12], frame[ETH_HDR + 13],
                frame[ETH_HDR + 14], frame[ETH_HDR + 15],
            ]);
            let dst = Ipv4Addr::from([
                frame[ETH_HDR + 16], frame[ETH_HDR + 17],
                frame[ETH_HDR + 18], frame[ETH_HDR + 19],
            ]);
            (IpAddr::V4(src), IpAddr::V4(dst))
        }
        IPV6_ET if frame.len() >= ETH_HDR + 40 => {
            let src: [u8; 16] = frame[ETH_HDR + 8..ETH_HDR + 24].try_into().unwrap();
            let dst: [u8; 16] = frame[ETH_HDR + 24..ETH_HDR + 40].try_into().unwrap();
            (IpAddr::V6(Ipv6Addr::from(src)), IpAddr::V6(Ipv6Addr::from(dst)))
        }
        _ => (IpAddr::V4(Ipv4Addr::UNSPECIFIED), IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
    }
}
