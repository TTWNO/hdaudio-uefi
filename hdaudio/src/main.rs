mod hda;

use syscall::iopl;
use std::error::Error;
use std::process::ExitCode;
use std::convert::TryFrom;
use std::fs::File;
use std::cell::RefCell;
use std::sync::Arc;
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
    println!("PCI FEATURES: {:?}", all_pci_features);

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
            PciFeatureInfo::MsiX(_) => panic!(),
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
        println!("Enabled MSI");

        Some(interrupt_handle)
    } else if pci_config.func.legacy_interrupt_pin.is_some() {
        println!("Legacy IRQ {}", irq);

        // legacy INTx# interrupt pins.
        Some(File::open(format!("irq:{}", irq)).expect("ihdad: failed to open legacy IRQ file"))
    } else {
        // no interrupts at all
        None
    }
}

fn main() -> Result<ExitCode, Box<dyn Error>> {
  println!("Opening Intel HDA"); 
  let mut pcid_handle = PcidServerHandle::connect_default().expect("ihdad: failed to setup channel to pcid");
  println!("Setup PCID Handle"); 

  let pci_config = pcid_handle.fetch_config().expect("ihdad: failed to fetch config");
  println!("Setup PCI Config"); 

  let mut name = pci_config.func.name();
  name.push_str("_ihda");
  println!("Name added _ihda"); 

  let bar = pci_config.func.bars[0];
  let bar_size = pci_config.func.bar_sizes[0];
  let bar_ptr = match bar {
      pcid_interface::PciBar::Memory32(ptr) => match ptr {
          0 => panic!("BAR 0 is mapped to address 0"),
          _ => ptr as u64,
      },
      pcid_interface::PciBar::Memory64(ptr) => match ptr {
          0 => panic!("BAR 0 is mapped to address 0"),
          _ => ptr,
      },
      other => panic!("Expected memory bar, found {}", other),
  };
  println!("Set up bar!"); 

  println!(" + IHDA {} on: {:#X} size: {}", name, bar_ptr, bar_size);

let address = unsafe {
	common::physmap(bar_ptr as usize, bar_size as usize, common::Prot::RW, common::MemoryType::Uncacheable)
		.expect("ihdad: failed to map address") as usize
};

  //TODO: MSI-X
  let mut irq_file = get_int_method(&mut pcid_handle).expect("ihdad: no interrupt file");

	let vend_prod:u32 = ((pci_config.func.venid as u32) << 16) | (pci_config.func.devid as u32);

	let device = Arc::new(RefCell::new(unsafe { hda::IntelHDA::new(address, vend_prod).expect("ihdad: failed to allocate device") }));
  device.borrow_mut().beep(20);
  
  Ok(ExitCode::SUCCESS)
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
