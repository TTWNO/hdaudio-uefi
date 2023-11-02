fn with_pci_func_raw<T, F: FnOnce(&PciFunc) -> T>(
    pci: &dyn CfgAccess,
    bus_num: u8,
    dev_num: u8,
    func_num: u8,
    function: F,
) -> T {
    let bus = PciBus { pci, num: bus_num };
    let dev = PciDev {
        bus: &bus,
        num: dev_num,
    };
    let func = PciFunc {
        dev: &dev,
        num: func_num,
    };
    function(&func)
}

use syscall::iopl;
use std::error::Error;
use std::process::ExitCode;
use std::convert::TryFrom;
use std::cell::RefCell;
use crate::pcid::pci::cap::CapabilityOffsetsIter;
use crate::pcid::pci::cap::CapabilitiesIter;
use crate::pcid::SubdriverArguments;
use crate::pcid::PciFeature;
use crate::pcid::SetFeatureInfo;
use crate::pcid::MsiSetFeatureInfo;
use crate::pcid::irq_helpers::allocate_single_interrupt_vector;
use crate::pcid::irq_helpers::read_bsp_apic_id;
use crate::pcid::PciFeatureInfo;
use crate::pcid::PcidServerHandle;
use std::fs::{metadata, read_dir, File};
use std::io::prelude::*;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::{i64, thread};

use log::{debug, error, info, trace, warn};

use crate::pcid::config::Config;
use crate::pcid::pci::cap::Capability as PciCapability;
use crate::pcid::pci::func::{ConfigReader, ConfigWriter};
use crate::pcid::pci::{
    CfgAccess, Pci, PciBar, PciBus, PciClass, PciDev, PciFunc, PciHeader, PciHeaderError,
    PciHeaderType, PciIter,
};
use crate::pcid::pcie::Pcie;

use crate::pcid::config;
use crate::pcid::driver_interface;
use crate::pcid::pci;
use crate::pcid::pcie;

pub struct DriverHandler {
    pub config: config::DriverConfig,
    pub bus_num: u8,
    pub dev_num: u8,
    pub func_num: u8,
    pub header: PciHeader,
    pub capabilities: Vec<(u8, PciCapability)>,

    pub state: Arc<State>,
}
impl DriverHandler {
    fn with_pci_func_raw<T, F: FnOnce(&PciFunc) -> T>(&self, function: F) -> T {
        with_pci_func_raw(
            self.state.preferred_cfg_access(),
            self.bus_num,
            self.dev_num,
            self.func_num,
            function,
        )
    }
    fn respond(
        &mut self,
        request: driver_interface::PcidClientRequest,
        args: &driver_interface::SubdriverArguments,
    ) -> driver_interface::PcidClientResponse {
        use crate::pcid::pci::cap::{MsiCapability, MsixCapability};
        use driver_interface::*;

        match request {
            PcidClientRequest::RequestCapabilities => PcidClientResponse::Capabilities(
                self.capabilities
                    .iter()
                    .map(|(_, capability)| capability.clone())
                    .collect::<Vec<_>>(),
            ),
            PcidClientRequest::RequestConfig => PcidClientResponse::Config(args.clone()),
            PcidClientRequest::RequestHeader => PcidClientResponse::Header(self.header.clone()),
            PcidClientRequest::RequestFeatures => PcidClientResponse::AllFeatures(
                self.capabilities
                    .iter()
                    .filter_map(|(_, capability)| match capability {
                        PciCapability::Msi(msi) => {
                            Some((PciFeature::Msi, FeatureStatus::enabled(msi.enabled())))
                        }
                        PciCapability::MsiX(msix) => Some((
                            PciFeature::MsiX,
                            FeatureStatus::enabled(msix.msix_enabled()),
                        )),
                        _ => None,
                    })
                    .collect(),
            ),
            PcidClientRequest::EnableFeature(feature) => match feature {
                PciFeature::Msi => {
                    let (offset, capability): (u8, &mut MsiCapability) = match self
                        .capabilities
                        .iter_mut()
                        .find_map(|&mut (offset, ref mut capability)| {
                            capability.as_msi_mut().map(|cap| (offset, cap))
                        }) {
                        Some(tuple) => tuple,
                        None => {
                            return PcidClientResponse::Error(
                                PcidServerResponseError::NonexistentFeature(feature),
                            )
                        }
                    };
                    unsafe {
                        with_pci_func_raw(
                            self.state.preferred_cfg_access(),
                            self.bus_num,
                            self.dev_num,
                            self.func_num,
                            |func| {
                                capability.set_enabled(true);
                                capability.write_message_control(func, offset);
                            },
                        );
                    }
                    PcidClientResponse::FeatureEnabled(feature)
                }
                PciFeature::MsiX => {
                    let (offset, capability): (u8, &mut MsixCapability) = match self
                        .capabilities
                        .iter_mut()
                        .find_map(|&mut (offset, ref mut capability)| {
                            capability.as_msix_mut().map(|cap| (offset, cap))
                        }) {
                        Some(tuple) => tuple,
                        None => {
                            return PcidClientResponse::Error(
                                PcidServerResponseError::NonexistentFeature(feature),
                            )
                        }
                    };
                    unsafe {
                        with_pci_func_raw(
                            self.state.preferred_cfg_access(),
                            self.bus_num,
                            self.dev_num,
                            self.func_num,
                            |func| {
                                capability.set_msix_enabled(true);
                                capability.write_a(func, offset);
                            },
                        );
                    }
                    PcidClientResponse::FeatureEnabled(feature)
                }
            },
            PcidClientRequest::FeatureStatus(feature) => PcidClientResponse::FeatureStatus(
                feature,
                match feature {
                    PciFeature::Msi => self
                        .capabilities
                        .iter()
                        .find_map(|(_, capability)| {
                            if let PciCapability::Msi(msi) = capability {
                                Some(FeatureStatus::enabled(msi.enabled()))
                            } else {
                                None
                            }
                        })
                        .unwrap_or(FeatureStatus::Disabled),
                    PciFeature::MsiX => self
                        .capabilities
                        .iter()
                        .find_map(|(_, capability)| {
                            if let PciCapability::MsiX(msix) = capability {
                                Some(FeatureStatus::enabled(msix.msix_enabled()))
                            } else {
                                None
                            }
                        })
                        .unwrap_or(FeatureStatus::Disabled),
                },
            ),
            PcidClientRequest::FeatureInfo(feature) => PcidClientResponse::FeatureInfo(
                feature,
                match feature {
                    PciFeature::Msi => {
                        if let Some(info) = self
                            .capabilities
                            .iter()
                            .find_map(|(_, capability)| capability.as_msi())
                        {
                            PciFeatureInfo::Msi(*info)
                        } else {
                            return PcidClientResponse::Error(
                                PcidServerResponseError::NonexistentFeature(feature),
                            );
                        }
                    }
                    PciFeature::MsiX => {
                        if let Some(info) = self
                            .capabilities
                            .iter()
                            .find_map(|(_, capability)| capability.as_msix())
                        {
                            PciFeatureInfo::MsiX(*info)
                        } else {
                            return PcidClientResponse::Error(
                                PcidServerResponseError::NonexistentFeature(feature),
                            );
                        }
                    }
                },
            ),
            PcidClientRequest::SetFeatureInfo(info_to_set) => match info_to_set {
                SetFeatureInfo::Msi(info_to_set) => {
                    if let Some((offset, info)) = self
                        .capabilities
                        .iter_mut()
                        .find_map(|(offset, capability)| Some((*offset, capability.as_msi_mut()?)))
                    {
                        if let Some(mme) = info_to_set.multi_message_enable {
                            if info.multi_message_capable() < mme || mme > 0b101 {
                                return PcidClientResponse::Error(
                                    PcidServerResponseError::InvalidBitPattern,
                                );
                            }
                            info.set_multi_message_enable(mme);
                        }
                        if let Some(message_addr) = info_to_set.message_address {
                            if message_addr & 0b11 != 0 {
                                return PcidClientResponse::Error(
                                    PcidServerResponseError::InvalidBitPattern,
                                );
                            }
                            info.set_message_address(message_addr);
                        }
                        if let Some(message_addr_upper) = info_to_set.message_upper_address {
                            info.set_message_upper_address(message_addr_upper);
                        }
                        if let Some(message_data) = info_to_set.message_data {
                            if message_data & ((1 << info.multi_message_enable()) - 1) != 0 {
                                return PcidClientResponse::Error(
                                    PcidServerResponseError::InvalidBitPattern,
                                );
                            }
                            info.set_message_data(message_data);
                        }
                        if let Some(mask_bits) = info_to_set.mask_bits {
                            info.set_mask_bits(mask_bits);
                        }
                        unsafe {
                            with_pci_func_raw(
                                self.state.preferred_cfg_access(),
                                self.bus_num,
                                self.dev_num,
                                self.func_num,
                                |func| {
                                    info.write_all(func, offset);
                                },
                            );
                        }
                        PcidClientResponse::SetFeatureInfo(PciFeature::Msi)
                    } else {
                        return PcidClientResponse::Error(
                            PcidServerResponseError::NonexistentFeature(PciFeature::Msi),
                        );
                    }
                }
                SetFeatureInfo::MsiX { function_mask } => {
                    if let Some((offset, info)) = self
                        .capabilities
                        .iter_mut()
                        .find_map(|(offset, capability)| Some((*offset, capability.as_msix_mut()?)))
                    {
                        if let Some(mask) = function_mask {
                            info.set_function_mask(mask);
                            unsafe {
                                with_pci_func_raw(
                                    self.state.preferred_cfg_access(),
                                    self.bus_num,
                                    self.dev_num,
                                    self.func_num,
                                    |func| {
                                        info.write_a(func, offset);
                                    },
                                );
                            }
                        }
                        PcidClientResponse::SetFeatureInfo(PciFeature::MsiX)
                    } else {
                        return PcidClientResponse::Error(
                            PcidServerResponseError::NonexistentFeature(PciFeature::MsiX),
                        );
                    }
                }
                _ => std::todo!(),
            },
            PcidClientRequest::ReadConfig(offset) => {
                let value = unsafe {
                    with_pci_func_raw(
                        self.state.preferred_cfg_access(),
                        self.bus_num,
                        self.dev_num,
                        self.func_num,
                        |func| func.read_u32(offset),
                    )
                };
                return PcidClientResponse::ReadConfig(value);
            }
            PcidClientRequest::WriteConfig(offset, value) => {
                unsafe {
                    with_pci_func_raw(
                        self.state.preferred_cfg_access(),
                        self.bus_num,
                        self.dev_num,
                        self.func_num,
                        |func| {
                            func.write_u32(offset, value);
                        },
                    );
                }
                return PcidClientResponse::WriteConfig;
            }
            _ => std::todo!(),
        }
    }
    fn handle_spawn(
        &mut self,
        pcid_to_client_write: &mut Sender<Vec<u8>>,
        pcid_from_client_read: &mut Receiver<Vec<u8>>,
        args: driver_interface::SubdriverArguments,
    ) {
        use driver_interface::*;

        while let Ok(msg) = recv(pcid_from_client_read) {
            let response = self.respond(msg, &args);
            send(pcid_to_client_write, &response).unwrap();
        }
    }
    pub fn try_handle_event(
        &mut self,
        pcid_to_client_write: &mut Sender<Vec<u8>>,
        pcid_from_client_read: &mut Receiver<Vec<u8>>,
        args: driver_interface::SubdriverArguments,
    ) {
        use driver_interface::*;

        if let Ok(msg) = recv(pcid_from_client_read) {
            let response = self.respond(msg, &args);
            send(pcid_to_client_write, &response).unwrap();
        }
    }
}

pub struct State {
    pub threads: Mutex<Vec<thread::JoinHandle<()>>>,
    pub pci: Arc<Pci>,
    pub pcie: Option<Pcie>,
}
impl State {
    pub fn preferred_cfg_access(&self) -> &dyn CfgAccess {
        // TODO
        //self.pcie.as_ref().map(|pcie| pcie as &dyn CfgAccess).unwrap_or(&*self.pci as &dyn CfgAccess)
        &*self.pci as &dyn CfgAccess
    }
}

use crossbeam::channel::{Sender, Receiver, bounded, SendError, TryRecvError, RecvError};
