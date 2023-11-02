use std::io::prelude::*;
use std::io::Bytes;
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;
use std::{env, io};

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;

pub use crate::pci::cap::Capability;
pub use crate::pci::msi;
pub use crate::pci::{PciBar, PciHeader};

pub mod irq_helpers;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[repr(u8)]
pub enum LegacyInterruptPin {
    /// INTa#
    IntA = 1,
    /// INTb#
    IntB = 2,
    /// INTc#
    IntC = 3,
    /// INTd#
    IntD = 4,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct PciFunction {
    /// Number of PCI bus
    pub bus_num: u8,

    /// Number of PCI device
    pub dev_num: u8,

    /// Number of PCI function
    pub func_num: u8,

    /// PCI Base Address Registers
    pub bars: [PciBar; 6],

    /// BAR sizes
    pub bar_sizes: [u32; 6],

    /// Legacy IRQ line: It's the responsibility of pcid to make sure that it be mapped in either
    /// the I/O APIC or the 8259 PIC, so that the subdriver can map the interrupt vector directly.
    /// The vector to map is always this field, plus 32.
    pub legacy_interrupt_line: u8,

    /// Legacy interrupt pin (INTx#), none if INTx# interrupts aren't supported at all.
    pub legacy_interrupt_pin: Option<LegacyInterruptPin>,

    /// Vendor ID
    pub venid: u16,
    /// Device ID
    pub devid: u16,
}
impl PciFunction {
    pub fn name(&self) -> String {
        format!(
            "pci-{:>02X}.{:>02X}.{:>02X}",
            self.bus_num, self.dev_num, self.func_num
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubdriverArguments {
    pub func: PciFunction,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum FeatureStatus {
    Enabled,
    Disabled,
}

impl FeatureStatus {
    pub fn enabled(enabled: bool) -> Self {
        if enabled {
            Self::Enabled
        } else {
            Self::Disabled
        }
    }
    pub fn is_enabled(&self) -> bool {
        if let &Self::Enabled = self {
            true
        } else {
            false
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum PciFeature {
    Msi,
    MsiX,
}
impl PciFeature {
    pub fn is_msi(&self) -> bool {
        if let &Self::Msi = self {
            true
        } else {
            false
        }
    }
    pub fn is_msix(&self) -> bool {
        if let &Self::MsiX = self {
            true
        } else {
            false
        }
    }
}
#[derive(Debug, Serialize, Deserialize)]
pub enum PciFeatureInfo {
    Msi(msi::MsiCapability),
    MsiX(msi::MsixCapability),
}

#[derive(Debug, Error)]
pub enum PcidClientHandleError {
    #[error("i/o error: {0}")]
    IoError(#[from] io::Error),

    #[error("JSON ser/de error: {0}")]
    SerializationError(#[from] bincode::Error),

    #[error("environment variable error: {0}")]
    EnvError(#[from] env::VarError),

    #[error("malformed fd: {0}")]
    EnvValidityError(std::num::ParseIntError),

    #[error("invalid response: {0:?}")]
    InvalidResponse(PcidClientResponse),
}
pub type Result<T, E = PcidClientHandleError> = std::result::Result<T, E>;

// TODO: Remove these "features" and just go strait to the actual thing.

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct MsiSetFeatureInfo {
    /// The Multi Message Enable field of the Message Control in the MSI Capability Structure,
    /// is the log2 of the interrupt vectors, minus one. Can only be 0b000..=0b101.
    pub multi_message_enable: Option<u8>,

    /// The system-specific message address, must be DWORD aligned.
    ///
    /// The message address contains things like the CPU that will be targeted, at least on
    /// x86_64.
    pub message_address: Option<u32>,

    /// The upper 32 bits of the 64-bit message address. Not guaranteed to exist, and is
    /// reserved on x86_64 (currently).
    pub message_upper_address: Option<u32>,

    /// The message data, containing the actual interrupt vector (lower 8 bits), etc.
    ///
    /// The spec mentions that the lower N bits can be modified, where N is the multi message
    /// enable, which means that the vector set here has to be aligned to that number, and that
    /// all vectors in that range have to be allocated.
    pub message_data: Option<u16>,

    /// A bitmap of the vectors that are masked. This field is not guaranteed (and not likely,
    /// at least according to the feature flags I got from QEMU), to exist.
    pub mask_bits: Option<u32>,
}

/// Some flags that might be set simultaneously, but separately.
#[derive(Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SetFeatureInfo {
    Msi(MsiSetFeatureInfo),

    MsiX {
        /// Masks the entire function, and all of its vectors.
        function_mask: Option<bool>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum PcidClientRequest {
    RequestConfig,
    RequestHeader,
    RequestFeatures,
    RequestCapabilities,
    EnableFeature(PciFeature),
    FeatureStatus(PciFeature),
    FeatureInfo(PciFeature),
    SetFeatureInfo(SetFeatureInfo),
    ReadConfig(u16),
    WriteConfig(u16, u32),
}

#[derive(Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum PcidServerResponseError {
    NonexistentFeature(PciFeature),
    InvalidBitPattern,
}

#[derive(Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum PcidClientResponse {
    Capabilities(Vec<Capability>),
    Config(SubdriverArguments),
    Header(PciHeader),
    AllFeatures(Vec<(PciFeature, FeatureStatus)>),
    FeatureEnabled(PciFeature),
    FeatureStatus(PciFeature, FeatureStatus),
    Error(PcidServerResponseError),
    FeatureInfo(PciFeature, PciFeatureInfo),
    SetFeatureInfo(PciFeature),
    ReadConfig(u32),
    WriteConfig,
}

// TODO: Ideally, pcid might have its own scheme, like lots of other Redox drivers, where this kind of IPC is done. Otherwise, instead of writing serde messages over
// a channel, the communication could potentially be done via mmap, using a channel
// very similar to crossbeam-channel or libstd's mpsc (except the cycle, enqueue and dequeue fields
// are stored in the same buffer as the actual data).
/// A handle from a `pcid` client (e.g. `ahcid`) to `pcid`.
pub struct PcidServerHandle {
    pcid_to_client: Arc<Mutex<Vec<u8>>>,
    pcid_from_client: Arc<Mutex<Vec<u8>>>,
}

pub(crate) fn send<W: Write + ?Sized, T: Serialize>(w: &mut W, message: &T) -> Result<()> {
    println!("send...");
    let mut data = Vec::new();
    bincode::serialize_into(&mut data, message)?;
    println!("...serialized ({})...", data.len());
    let length_bytes = u64::to_le_bytes(data.len() as u64);
    println!("Made into bytes");
    w.write_all(&length_bytes)?;
    println!("Wrote byte length");
    w.write_all(&data)?;
    println!("written");
    Ok(())
}
pub(crate) fn recv<R: Read + ?Sized, T: DeserializeOwned>(r: &mut R) -> Result<T> {
    println!("recv...");
    let mut length_bytes = [0u8; 8];
    r.read_exact(&mut length_bytes)?;
    let length = u64::from_le_bytes(length_bytes);
    println!("{}...", length);
    if length > 0x100_000 {
        panic!("pcid_interface: buffer too large");
    }
    let mut data = vec![0u8; length as usize];
    r.read_exact(&mut data)?;
    println!("reading...");
    println!("{:?}", data);

    let b = bincode::deserialize_from(&data[..])?;
    println!("done");
    Ok(b)
}

impl PcidServerHandle {
    pub fn connect(
        pcid_to_client: Arc<Mutex<Vec<u8>>>,
        pcid_from_client: Arc<Mutex<Vec<u8>>>,
    ) -> Result<Self> {
        Ok(Self {
            pcid_to_client,
            pcid_from_client,
        })
    }
    pub fn connect_default() -> Result<Self> {
        println!("Try connect default!");
        let pcid_to_client_fd = Arc::new(Mutex::new(Vec::new()));
        let pcid_from_client_fd = Arc::new(Mutex::new(Vec::new()));
        println!("Created files");

        Self::connect(pcid_to_client_fd, pcid_from_client_fd)
    }
    pub(crate) fn send(&mut self, req: &PcidClientRequest) -> Result<()> {
        let mut tex = self.pcid_to_client.lock().unwrap();
        send(&mut *tex, req)
    }
    pub(crate) fn recv(&mut self) -> Result<PcidClientResponse> {
        let mut slice = &self.pcid_from_client.lock().unwrap()[..];
        recv(&mut slice)
    }
    pub fn fetch_config(&mut self) -> Result<SubdriverArguments> {
        println!("Try to send");
        self.send(&PcidClientRequest::RequestConfig)?;
        println!("sent");
        match self.recv()? {
            PcidClientResponse::Config(a) => Ok(a),
            other => Err(PcidClientHandleError::InvalidResponse(other)),
        }
    }

    pub fn get_capabilities(&mut self) -> Result<Vec<Capability>> {
        self.send(&PcidClientRequest::RequestCapabilities)?;

        match self.recv()? {
            PcidClientResponse::Capabilities(a) => Ok(a),
            other => Err(PcidClientHandleError::InvalidResponse(other)),
        }
    }

    pub fn fetch_header(&mut self) -> Result<PciHeader> {
        self.send(&PcidClientRequest::RequestHeader)?;
        match self.recv()? {
            PcidClientResponse::Header(a) => Ok(a),
            other => Err(PcidClientHandleError::InvalidResponse(other)),
        }
    }
    pub fn fetch_all_features(&mut self) -> Result<Vec<(PciFeature, FeatureStatus)>> {
        self.send(&PcidClientRequest::RequestFeatures)?;
        match self.recv()? {
            PcidClientResponse::AllFeatures(a) => Ok(a),
            other => Err(PcidClientHandleError::InvalidResponse(other)),
        }
    }
    pub fn feature_status(&mut self, feature: PciFeature) -> Result<FeatureStatus> {
        self.send(&PcidClientRequest::FeatureStatus(feature))?;
        match self.recv()? {
            PcidClientResponse::FeatureStatus(feat, status) if feat == feature => Ok(status),
            other => Err(PcidClientHandleError::InvalidResponse(other)),
        }
    }
    pub fn enable_feature(&mut self, feature: PciFeature) -> Result<()> {
        self.send(&PcidClientRequest::EnableFeature(feature))?;
        match self.recv()? {
            PcidClientResponse::FeatureEnabled(feat) if feat == feature => Ok(()),
            other => Err(PcidClientHandleError::InvalidResponse(other)),
        }
    }
    pub fn feature_info(&mut self, feature: PciFeature) -> Result<PciFeatureInfo> {
        self.send(&PcidClientRequest::FeatureInfo(feature))?;
        match self.recv()? {
            PcidClientResponse::FeatureInfo(feat, info) if feat == feature => Ok(info),
            other => Err(PcidClientHandleError::InvalidResponse(other)),
        }
    }
    pub fn set_feature_info(&mut self, info: SetFeatureInfo) -> Result<()> {
        self.send(&PcidClientRequest::SetFeatureInfo(info))?;
        match self.recv()? {
            PcidClientResponse::SetFeatureInfo(_) => Ok(()),
            other => Err(PcidClientHandleError::InvalidResponse(other)),
        }
    }
    pub unsafe fn read_config(&mut self, offset: u16) -> Result<u32> {
        self.send(&PcidClientRequest::ReadConfig(offset))?;
        match self.recv()? {
            PcidClientResponse::ReadConfig(value) => Ok(value),
            other => Err(PcidClientHandleError::InvalidResponse(other)),
        }
    }
    pub unsafe fn write_config(&mut self, offset: u16, value: u32) -> Result<()> {
        self.send(&PcidClientRequest::WriteConfig(offset, value))?;
        match self.recv()? {
            PcidClientResponse::WriteConfig => Ok(()),
            other => Err(PcidClientHandleError::InvalidResponse(other)),
        }
    }
}
