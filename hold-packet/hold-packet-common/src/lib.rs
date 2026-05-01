#![no_std]

/// Capture Mode for a Captured IP
/// - PassThrough (0): service is live; packets flow normally
/// - Hold (1): service is scaled-to-zero; packets are redirected to the TAP device
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureMode {
    PassThrough = 0,
    Hold = 1,
}

impl CaptureMode {
    /// Returns true if the mode is Hold (packets should be redirected)
    pub fn is_hold(&self) -> bool {
        *self == CaptureMode::Hold
    }
}

impl Default for CaptureMode {
    fn default() -> Self {
        CaptureMode::PassThrough
    }
}

#[cfg(feature = "user")]
impl core::convert::TryFrom<u8> for CaptureMode {
    type Error = InvalidCaptureModeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(CaptureMode::PassThrough),
            1 => Ok(CaptureMode::Hold),
            _ => Err(InvalidCaptureModeError(value)),
        }
    }
}

#[cfg(feature = "user")]
#[derive(Clone, Copy, Debug)]
pub struct InvalidCaptureModeError(pub u8);

#[cfg(feature = "user")]
impl core::fmt::Display for InvalidCaptureModeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid CaptureMode discriminant {}", self.0)
    }
}

#[cfg(feature = "user")]
impl core::error::Error for InvalidCaptureModeError {}

#[cfg(feature = "user")]
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct RawStateEntry {
    pub last_seen_ns: u64,
    pub packet_count: u64,
    pub mode: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct StateEntry {
    pub last_seen_ns: u64,
    pub packet_count: u64,
    pub mode: CaptureMode,
}

// Safety: StateEntry is #[repr(C)] with no padding and only Pod fields.
#[cfg(feature = "user")]
unsafe impl aya::Pod for StateEntry {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for RawStateEntry {}

#[cfg(feature = "user")]
impl TryFrom<RawStateEntry> for StateEntry {
    type Error = InvalidCaptureModeError;

    fn try_from(value: RawStateEntry) -> Result<Self, Self::Error> {
        Ok(Self {
            last_seen_ns: value.last_seen_ns,
            packet_count: value.packet_count,
            mode: CaptureMode::try_from(value.mode)?,
        })
    }
}

#[cfg(feature = "user")]
impl From<StateEntry> for RawStateEntry {
    fn from(value: StateEntry) -> Self {
        Self {
            last_seen_ns: value.last_seen_ns,
            packet_count: value.packet_count,
            mode: value.mode as u8,
        }
    }
}

