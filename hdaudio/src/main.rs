mod hda;

use syscall::iopl;
use std::error::Error;
use std::process::ExitCode;
use std::convert::TryFrom;
use std::cell::RefCell;
use pcid_interface::pci::cap::CapabilityOffsetsIter;
use pcid_interface::pci::cap::CapabilitiesIter;
use pcid_interface::PciFeature;
use pcid_interface::SetFeatureInfo;
use pcid_interface::MsiSetFeatureInfo;
use pcid_interface::irq_helpers::allocate_single_interrupt_vector;
use pcid_interface::irq_helpers::read_bsp_apic_id;
use pcid_interface::PciFeatureInfo;
use pcid_interface::PcidServerHandle;

#[cfg(not(target_arch = "x85_64"))]
fn get_int_method(pcid_handle: &mut PcidServerHandle) -> Option<File> {
    let pci_config = pcid_handle.fetch_config().expect("ihdad: failed to fetch config");
    let irq = pci_config.func.legacy_interrupt_line;

    if pci_config.func.legacy_interrupt_pin.is_some() {
        // legacy INTx# interrupt pins.
        Some(File::open(format!("irq:{}", irq)).expect("ihdad: failed to open legacy IRQ file"))
    } else {
        // no interrupts at all
        None
    }
}

#[cfg(target_arch = "x85_64")]
fn get_int_method(pcid_handle: &mut PcidServerHandle) -> Option<File> {
    let pci_config = pcid_handle.fetch_config().expect("ihdad: failed to fetch config");

    let irq = pci_config.func.legacy_interrupt_line;

    let all_pci_features = pcid_handle.fetch_all_features().expect("ihdad: failed to fetch pci features");
    std::println!("PCI FEATURES: {:?}", all_pci_features);

    let (has_msi, mut msi_enabled) = all_pci_features.iter().map(|(feature, status)| (feature.is_msi(), status.is_enabled())).find(|&(f, _)| f).unwrap_or((false, false));
    let (has_msix, mut msix_enabled) = all_pci_features.iter().map(|(feature, status)| (feature.is_msix(), status.is_enabled())).find(|&(f, _)| f).unwrap_or((false, false));

    if has_msi && !msi_enabled && !has_msix {
        msi_enabled = true;
    }
    if has_msix && !msix_enabled {
        msix_enabled = true;
    }

    if msi_enabled && !msix_enabled {
        use pcid_interface::msi::x86_64::{DeliveryMode, self as x86_64_msix};

        let capability = match pcid_handle.feature_info(PciFeature::Msi).expect("ihdad: failed to retrieve the MSI capability structure from pcid") {
            PciFeatureInfo::Msi(s) => s,
            PciFeatureInfo::MsiX(_) => std::panic!(),
        };
        // TODO: Allow allocation of up to 32 vectors.

        // TODO: Find a way to abstract this away, potantially as a helper module for
        // pcid_interface, so that this can be shared between nvmed, xhcid, ixgebd, etc..

        let destination_id = read_bsp_apic_id().expect("ihdad: failed to read BSP apic id");
        let lapic_id = u8::try_from(destination_id).expect("CPU id didn't fit inside u8");
        let msg_addr = x86_64_msix::message_address(lapic_id, false, false);

        let (vector, interrupt_handle) = allocate_single_interrupt_vector(destination_id).expect("ihdad: failed to allocate interrupt vector").expect("ihdad: no interrupt vectors left");
        let msg_data = x86_64_msix::message_data_edge_triggered(DeliveryMode::Fixed, vector);

        let set_feature_info = MsiSetFeatureInfo {
            multi_message_enable: Some(0),
            message_address: Some(msg_addr),
            message_upper_address: Some(0),
            message_data: Some(msg_data as u16),
            mask_bits: None,
        };
        pcid_handle.set_feature_info(SetFeatureInfo::Msi(set_feature_info)).expect("ihdad: failed to set feature info");

        pcid_handle.enable_feature(PciFeature::Msi).expect("ihdad: failed to enable MSI");
        std::println!("Enabled MSI");

        Some(interrupt_handle)
    } else if pci_config.func.legacy_interrupt_pin.is_some() {
        std::println!("Legacy IRQ {}", irq);

        // legacy INTx# interrupt pins.
        Some(File::open(format!("irq:{}", irq)).expect("ihdad: failed to open legacy IRQ file"))
    } else {
        // no interrupts at all
        None
    }
}

fn main() {
  let (mut pci_from_write, pci_from_read) = bounded(1024);
  let (pci_to_write, mut pci_to_read) = bounded(1024);
  pci_main(&mut pci_from_write, &mut pci_to_read);
  hda_main(pci_to_write, pci_from_read);
}

fn hda_main(pci_to_write: Sender<Vec<u8>>, pci_from_read: Receiver<Vec<u8>>) {
  std::println!("Opening Intel HDA"); 
  let mut pcid_handle = PcidServerHandle::connect(pci_to_write, pci_from_read).expect("ihdad: failed to setup channel to pcid");
  std::println!("Setup PCID Handle"); 

  let pci_config = pcid_handle.fetch_config().expect("ihdad: failed to fetch config");
  std::println!("Setup PCI Config"); 

  let mut name = pci_config.func.name();
  name.push_str("_ihda");
  std::println!("Name added _ihda"); 

  let bar = pci_config.func.bars[0];
  let bar_size = pci_config.func.bar_sizes[0];
  let bar_ptr = match bar {
      pcid_interface::PciBar::Memory32(ptr) => match ptr {
          0 => std::panic!("BAR 0 is mapped to address 0"),
          _ => ptr as u64,
      },
      pcid_interface::PciBar::Memory64(ptr) => match ptr {
          0 => std::panic!("BAR 0 is mapped to address 0"),
          _ => ptr,
      },
      other => std::panic!("Expected memory bar, found {}", other),
  };
  std::println!("Set up bar!"); 

  std::println!(" + IHDA {} on: {:#X} size: {}", name, bar_ptr, bar_size);

let address = unsafe {
	common::physmap(bar_ptr as usize, bar_size as usize, common::Prot::RW, common::MemoryType::Uncacheable)
		.expect("ihdad: failed to map address") as usize
};
  std::println!("Address mapped properly!");

  //TODO: MSI-X
  let mut irq_file = get_int_method(&mut pcid_handle).expect("ihdad: no interrupt file");

	let vend_prod:u32 = ((pci_config.func.venid as u32) << 16) | (pci_config.func.devid as u32);

	let device = Arc::new(RefCell::new(unsafe { hda::IntelHDA::new(address, vend_prod).expect("ihdad: failed to allocate device") }));
  device.borrow_mut().beep(20);
}

////#![deny(warnings)]
//#![feature(int_roundings)]
//
//extern crate bitflags;
//extern crate spin;
//extern crate syscall;
//extern crate event;
//
//use std::convert::TryFrom;
//use std::usize;
//use std::fs::File;
//use std::io::{ErrorKind, Read, Write, Result};
//use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
//use syscall::{Packet, SchemeBlockMut, EventFlags};
//use std::cell::RefCell;
//use std::sync::Arc;
//
//use event::EventQueue;
//use pcid_interface::{MsiSetFeatureInfo, PcidServerHandle, PciFeature, PciFeatureInfo, SetFeatureInfo};
//use pcid_interface::irq_helpers::{read_bsp_apic_id, allocate_single_interrupt_vector};
//use redox_log::{OutputBuilder, RedoxLogger};
//
//pub mod hda;
//
//                 VEND:PROD
//    Virtualbox   8086:2668
//    QEMU ICH9    8086:293E
//    82801H ICH8  8086:284B
//*/
//
//fn daemon(daemon: redox_daemon::Daemon) -> ! {
//		let mut event_queue = EventQueue::<usize>::new().expect("ihdad: Could not create event queue.");
//
//        syscall::setrens(0, 0).expect("ihdad: failed to enter null namespace");
//
//		let todo = Arc::new(RefCell::new(Vec::<Packet>::new()));
//
//		let todo_irq = todo.clone();
//		let device_irq = device.clone();
//		let socket_irq = socket.clone();
//		event_queue.add(irq_file.as_raw_fd(), move |_event| -> Result<Option<usize>> {
//			let mut irq = [0; 8];
//			irq_file.read(&mut irq)?;
//
//			if device_irq.borrow_mut().irq() {
//				irq_file.write(&mut irq)?;
//
//				let mut todo = todo_irq.borrow_mut();
//				let mut i = 0;
//				while i < todo.len() {
//					if let Some(a) = device_irq.borrow_mut().handle(&mut todo[i]) {
//	                    let mut packet = todo.remove(i);
//	                    packet.a = a;
//						socket_irq.borrow_mut().write(&packet)?;
//	                } else {
//	                    i += 1;
//					}
//				}
//
//				/*
//				let next_read = device_irq.next_read();
//				if next_read > 0 {
//					return Ok(Some(next_read));
//				}
//				*/
//			}
//			Ok(None)
//		}).expect("ihdad: failed to catch events on IRQ file");
//		let socket_fd = socket.borrow().as_raw_fd();
//		let socket_packet = socket.clone();
//		event_queue.add(socket_fd, move |_event| -> Result<Option<usize>> {
//			loop {
//				let mut packet = Packet::default();
//				match socket_packet.borrow_mut().read(&mut packet) {
//		            Ok(0) => return Ok(Some(0)),
//		            Ok(_) => (),
//		            Err(err) => if err.kind() == ErrorKind::WouldBlock {
//		                break;
//		            } else {
//		                return Err(err);
//		            }
//				}
//
//				if let Some(a) = device.borrow_mut().handle(&mut packet) {
//					packet.a = a;
//					socket_packet.borrow_mut().write(&packet)?;
//				} else {
//					todo.borrow_mut().push(packet);
//				}
//			}
//
//			/*
//			let next_read = device.borrow().next_read();
//			if next_read > 0 {
//				return Ok(Some(next_read));
//			}
//			*/
//
//			Ok(None)
//		}).expect("ihdad: failed to catch events on IRQ file");
//
//		for event_count in event_queue.trigger_all(event::Event {
//			fd: 0,
//			flags: EventFlags::empty(),
//		}).expect("ihdad: failed to trigger events") {
//			socket.borrow_mut().write(&Packet {
//				id: 0,
//				pid: 0,
//				uid: 0,
//				gid: 0,
//				a: syscall::number::SYS_FEVENT,
//				b: 0,
//				c: syscall::flag::EVENT_READ.bits(),
//				d: event_count
//			}).expect("ihdad: failed to write event");
//		}
//
//		loop {
//			{
//				//device_loop.borrow_mut().handle_interrupts();
//			}
//			let event_count = event_queue.run().expect("ihdad: failed to handle events");
//			if event_count == 0 {
//				//TODO: Handle todo
//				break;
//			}
//
//			socket.borrow_mut().write(&Packet {
//				id: 0,
//				pid: 0,
//				uid: 0,
//				gid: 0,
//				a: syscall::number::SYS_FEVENT,
//				b: 0,
//				c: syscall::flag::EVENT_READ.bits(),
//				d: event_count
//			}).expect("ihdad: failed to write event");
//		}
//	}
//
//    std::process::exit(0);
//}
//
//fn main() {
//	// Daemonize
//    redox_daemon::Daemon::new(daemon).expect("ihdad: failed to daemonize");
//}
use std::fs::{metadata, read_dir, File};
use std::io::prelude::*;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::{i64, thread};

use log::{debug, error, info, trace, warn};

use pcid_interface::config::Config;
use pcid_interface::pci::cap::Capability as PciCapability;
use pcid_interface::pci::func::{ConfigReader, ConfigWriter};
use pcid_interface::pci::{
    CfgAccess, Pci, PciBar, PciBus, PciClass, PciDev, PciFunc, PciHeader, PciHeaderError,
    PciHeaderType, PciIter,
};
use pcid_interface::pcie::Pcie;

use pcid_interface::config;
use pcid_interface::driver_interface;
use pcid_interface::pci;
use pcid_interface::pcie;

//#[derive(StructOpt)]
//#[structopt(about)]
//struct Args {
//    #[structopt(short, long,
//        help="Increase logging level once for each arg.", parse(from_occurrences))]
//    verbose: u8,
//
//    #[structopt(
//        help="A path to a pcid config file or a directory that contains pcid config files.")]
//    config_path: Option<String>,
//}
//
pub struct DriverHandler {
    config: config::DriverConfig,
    bus_num: u8,
    dev_num: u8,
    func_num: u8,
    header: PciHeader,
    capabilities: Vec<(u8, PciCapability)>,

    state: Arc<State>,
}
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
        use pcid_interface::pci::cap::{MsiCapability, MsixCapability};
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
        mut self,
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
}

pub struct State {
    threads: Mutex<Vec<thread::JoinHandle<()>>>,
    pci: Arc<Pci>,
    pcie: Option<Pcie>,
}
impl State {
    fn preferred_cfg_access(&self) -> &dyn CfgAccess {
        // TODO
        //self.pcie.as_ref().map(|pcie| pcie as &dyn CfgAccess).unwrap_or(&*self.pci as &dyn CfgAccess)
        &*self.pci as &dyn CfgAccess
    }
}

use crossbeam::channel::{Sender, Receiver, bounded};

fn handle_parsed_header(
    state: Arc<State>,
    config: &Config,
    bus_num: u8,
    dev_num: u8,
    func_num: u8,
    header: PciHeader,
    pcid_to_write: Sender<Vec<u8>>,
    pcid_from_read: Receiver<Vec<u8>>
) {
    let pci = state.preferred_cfg_access();

    let raw_class: u8 = header.class().into();
    let mut string = format!(
        "PCI {:>02X}/{:>02X}/{:>02X} {:>04X}:{:>04X} {:>02X}.{:>02X}.{:>02X}.{:>02X} {:?}",
        bus_num,
        dev_num,
        func_num,
        header.vendor_id(),
        header.device_id(),
        raw_class,
        header.subclass(),
        header.interface(),
        header.revision(),
        header.class()
    );
    match header.class() {
        PciClass::Legacy if header.subclass() == 1 => string.push_str("  VGA CTL"),
        PciClass::Storage => match header.subclass() {
            0x01 => {
                string.push_str(" IDE");
            }
            0x06 => {
                if header.interface() == 0 {
                    string.push_str(" SATA VND");
                } else if header.interface() == 1 {
                    string.push_str(" SATA AHCI");
                }
            }
            _ => (),
        },
        PciClass::SerialBus => match header.subclass() {
            0x03 => match header.interface() {
                0x00 => {
                    string.push_str(" UHCI");
                }
                0x10 => {
                    string.push_str(" OHCI");
                }
                0x20 => {
                    string.push_str(" EHCI");
                }
                0x30 => {
                    string.push_str(" XHCI");
                }
                _ => (),
            },
            _ => (),
        },
        _ => (),
    }

    for (i, bar) in header.bars().iter().enumerate() {
        if !bar.is_none() {
            string.push_str(&format!(" {}={}", i, bar));
        }
    }

    std::println!("{}", string);

    for driver in config.drivers.iter() {
        if let Some(class) = driver.class {
            if class != raw_class {
                continue;
            }
        }

        if let Some(subclass) = driver.subclass {
            if subclass != header.subclass() {
                continue;
            }
        }

        if let Some(interface) = driver.interface {
            if interface != header.interface() {
                continue;
            }
        }

        if let Some(ref ids) = driver.ids {
            let mut device_found = false;
            for (vendor, devices) in ids {
                let vendor_without_prefix = vendor.trim_start_matches("0x");
                let vendor = i64::from_str_radix(vendor_without_prefix, 16).unwrap() as u16;

                if vendor != header.vendor_id() {
                    continue;
                }

                for device in devices {
                    if *device == header.device_id() {
                        device_found = true;
                        break;
                    }
                }
            }
            if !device_found {
                continue;
            }
        } else {
            if let Some(vendor) = driver.vendor {
                if vendor != header.vendor_id() {
                    continue;
                }
            }

            if let Some(device) = driver.device {
                if device != header.device_id() {
                    continue;
                }
            }
        }

        if let Some(ref device_id_range) = driver.device_id_range {
            if header.device_id() < device_id_range.start
                || device_id_range.end <= header.device_id()
            {
                continue;
            }
        }

        if let Some(ref args) = driver.command {
            // Enable bus mastering, memory space, and I/O space
            unsafe {
                let mut data = pci.read(bus_num, dev_num, func_num, 0x04);
                data |= 7;
                pci.write(bus_num, dev_num, func_num, 0x04, data);
            }

            // Set IRQ line to 9 if not set
            let mut irq;
            let mut interrupt_pin;

            unsafe {
                let mut data = pci.read(bus_num, dev_num, func_num, 0x3C);
                irq = (data & 0xFF) as u8;
                interrupt_pin = ((data & 0x0000_FF00) >> 8) as u8;
                if irq == 0xFF {
                    irq = 9;
                }
                data = (data & 0xFFFFFF00) | irq as u32;
                pci.write(bus_num, dev_num, func_num, 0x3C, data);
            };

            // Find BAR sizes
            //TODO: support 64-bit BAR sizes?
            let mut bars = [PciBar::None; 6];
            let mut bar_sizes = [0; 6];
            unsafe {
                let count = match header.header_type() {
                    PciHeaderType::GENERAL => 6,
                    PciHeaderType::PCITOPCI => 2,
                    _ => 0,
                };

                for i in 0..count {
                    bars[i] = header.get_bar(i);

                    let offset = 0x10 + (i as u8) * 4;

                    let original = pci.read(bus_num, dev_num, func_num, offset.into());
                    pci.write(bus_num, dev_num, func_num, offset.into(), 0xFFFFFFFF);

                    let new = pci.read(bus_num, dev_num, func_num, offset.into());
                    pci.write(bus_num, dev_num, func_num, offset.into(), original);

                    let masked = if new & 1 == 1 {
                        new & 0xFFFFFFFC
                    } else {
                        new & 0xFFFFFFF0
                    };

                    let size = (!masked).wrapping_add(1);
                    bar_sizes[i] = if size <= 1 { 0 } else { size };
                }
            }

            let capabilities = if header.status() & (1 << 4) != 0 {
                let bus = PciBus {
                    pci: state.preferred_cfg_access(),
                    num: bus_num,
                };
                let dev = PciDev {
                    bus: &bus,
                    num: dev_num,
                };
                let func = PciFunc {
                    dev: &dev,
                    num: func_num,
                };
                CapabilitiesIter {
                    inner: CapabilityOffsetsIter::new(header.cap_pointer(), &func),
                }
                .collect::<Vec<_>>()
            } else {
                Vec::new()
            };
            use driver_interface::LegacyInterruptPin;

            let legacy_interrupt_pin = match interrupt_pin {
                0 => None,
                1 => Some(LegacyInterruptPin::IntA),
                2 => Some(LegacyInterruptPin::IntB),
                3 => Some(LegacyInterruptPin::IntC),
                4 => Some(LegacyInterruptPin::IntD),

                other => {
                    warn!("pcid: invalid interrupt pin: {}", other);
                    None
                }
            };

            let func = driver_interface::PciFunction {
                bars,
                bar_sizes,
                bus_num,
                dev_num,
                func_num,
                devid: header.device_id(),
                legacy_interrupt_line: irq,
                legacy_interrupt_pin,
                venid: header.vendor_id(),
            };

            let subdriver_args = driver_interface::SubdriverArguments { func };

            let mut args = args.iter();
            if let Some(program) = args.next() {
                let mut command = Command::new(program);
                for arg in args {
                    let arg = match arg.as_str() {
                        "$BUS" => format!("{:>02X}", bus_num),
                        "$DEV" => format!("{:>02X}", dev_num),
                        "$FUNC" => format!("{:>02X}", func_num),
                        "$NAME" => func.name(),
                        "$BAR0" => format!("{}", bars[0]),
                        "$BAR1" => format!("{}", bars[1]),
                        "$BAR2" => format!("{}", bars[2]),
                        "$BAR3" => format!("{}", bars[3]),
                        "$BAR4" => format!("{}", bars[4]),
                        "$BAR5" => format!("{}", bars[5]),
                        "$BARSIZE0" => format!("{:>08X}", bar_sizes[0]),
                        "$BARSIZE1" => format!("{:>08X}", bar_sizes[1]),
                        "$BARSIZE2" => format!("{:>08X}", bar_sizes[2]),
                        "$BARSIZE3" => format!("{:>08X}", bar_sizes[3]),
                        "$BARSIZE4" => format!("{:>08X}", bar_sizes[4]),
                        "$BARSIZE5" => format!("{:>08X}", bar_sizes[5]),
                        "$IRQ" => format!("{}", irq),
                        "$VENID" => format!("{:>04X}", header.vendor_id()),
                        "$DEVID" => format!("{:>04X}", header.device_id()),
                        _ => arg.clone(),
                    };
                    command.arg(&arg);
                }

                std::println!("PCID SPAWN {:?}", command);

                //TODO:
                //this is RedoxOS's way of doing shared memory
                //two raw file descriptors,
                //reader on one side
                //writer on the other, but attached via the same
                //file descriptor.
                //the TO/FROM are id 1/2
                //then there are two references handed out
                //one to the local handle_spawn function
                //and the other to the "global" envrionemtn variable space
                //with the TO_READ/FROM_WRITE being shared
                //and TO_WRITE/FROM_READ being moved to a local spawned thread
                //to configure HDAudio, we will need to run this function using shared memory, ideally Arc<Mutex<Vec<u8>>> since this creates shared, mutally excluusive access to what can become raw buffers (&mut [u8])
                //there will need to be two buffers, then you can pass copies of the Arc<_> to the two sides.
                //they can unlock them when needed
                //hopefully locking doesn't cause problems with timing.
                // Redox also wants to set envrionemnt variables ( as set in handle_spanw
                // and use that to launch a separate command
                // in this case, it actually looks up a driver's `main` to run.
                // it seems every driver runs in its own process.
                // we need to combine everyting to run in one binary.
                // how to share all these variables, and launch with all these options, I'm not really sure....
                // so here we'd want to find `hdaudio` outputs, and then figure out how to pass all these arguments
                // also, microkernal for the win, I never realized how clean it was to run stuff like this in a uKernal environment.
                // I'd be interested on adding development to this platform in the future
                // maybe get atspi going? with help from the main developer? (remember he is in the Odilia channel)

                // try to hook into spawning a separate function but not a separate command

                // TODO: fix command issues
                /*
                match command.spawn() {
                    Ok(mut child) => {
                        let driver_handler = DriverHandler {
                            bus_num,
                            dev_num,
                            func_num,
                            config: driver.clone(),
                            header,
                            state: Arc::clone(&state),
                            capabilities,
                        };
                        let thread = thread::spawn(move || {
                            // RFLAGS are no longer kept in the relibc clone() implementation.
                            unsafe {
                                syscall::iopl(3).expect("pcid: failed to set IOPL");
                            }

                            driver_handler.handle_spawn(
                                pcid_to_client_write,
                                pcid_from_client_read,
                                subdriver_args,
                            );
                        });
                        match child.wait() {
                            Ok(_status) => (),
                            Err(err) => error!("pcid: failed to wait for {:?}: {}", command, err),
                        }
                    }
                    Err(err) => error!("pcid: failed to execute {:?}: {}", command, err),
                }
                */
            }
        }
    }
}

fn pci_main(
  pcid_from_write: &mut Sender<Vec<u8>>,
  pcid_to_read: &mut Receiver<Vec<u8>>
) {
    let mut config = Config::default();

    let pci = Arc::new(Pci::new());

    let state = Arc::new(State {
        pci: Arc::clone(&pci),
        pcie: match Pcie::new(Arc::clone(&pci)) {
            Ok(pcie) => Some(pcie),
            Err(error) => {
                std::println!("Couldn't retrieve PCIe info, perhaps the kernel is not compiled with acpi? Using the PCI 3.0 configuration space instead. Error: {:?}", error);
                None
            }
        },
        threads: Mutex::new(Vec::new()),
    });

    let pci = state.preferred_cfg_access();

    std::println!("PCI BS/DV/FN VEND:DEVI CL.SC.IN.RV");

    let mut bus_nums = vec![0];
    let mut bus_i = 0;
    'bus: while bus_i < bus_nums.len() {
        let bus_num = bus_nums[bus_i];
        std::println!("BNum: {}", bus_num);
        bus_i += 1;

        let bus = PciBus { pci, num: bus_num };
        'dev: for dev in bus.devs() {
            for func in dev.funcs() {
                let func_num = func.num;
                match PciHeader::from_reader(func) {
                    Ok(header) => {
                        handle_parsed_header(
                            Arc::clone(&state),
                            &config,
                            bus.num,
                            dev.num,
                            func_num,
                            header,
                            pcid_from_write.clone(),
                            pcid_to_read.clone(),
                        );
                        if let PciHeader::PciToPci {
                            secondary_bus_num, ..
                        } = header
                        {
                            bus_nums.push(secondary_bus_num);
                        }
                    }
                    Err(PciHeaderError::NoDevice) => {
                        if func_num == 0 {
                            if dev.num == 0 {
                                trace!("PCI {:>02X}: no bus", bus.num);
                                continue 'bus;
                            } else {
                                trace!("PCI {:>02X}/{:>02X}: no dev", bus.num, dev.num);
                                continue 'dev;
                            }
                        }
                    }
                    Err(PciHeaderError::UnknownHeaderType(id)) => {
                        warn!("pcid: unknown header type: {}", id);
                    }
                }
            }
        }
    }

    for thread in state.threads.lock().unwrap().drain(..) {
        thread.join().unwrap();
    }
}
