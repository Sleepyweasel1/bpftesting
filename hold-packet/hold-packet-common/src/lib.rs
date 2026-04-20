#![no_std]
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct StateEntry {
    pub last_seen_ns: u64,
    pub packet_count: u64,
    pub replay: u8,
}

// Safety: StateEntry is #[repr(C)] with no padding and only Pod fields.
#[cfg(feature = "user")]
unsafe impl aya::Pod for StateEntry {}

