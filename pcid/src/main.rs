use std::fs::{metadata, read_dir, File};
use std::io::prelude::*;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::{i64, thread};

use log::{debug, error, info, trace, warn};

use crate::config::Config;
use crate::pci::cap::Capability as PciCapability;
use crate::pci::func::{ConfigReader, ConfigWriter};
use crate::pci::{
    CfgAccess, Pci, PciBar, PciBus, PciClass, PciDev, PciFunc, PciHeader, PciHeaderError,
    PciHeaderType, PciIter,
};
use crate::pcie::Pcie;

mod config;
mod driver_interface;
mod pci;
mod pcie;

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
        use crate::pci::cap::{MsiCapability, MsixCapability};
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
        }
    }
    fn handle_spawn(
        mut self,
        pcid_to_client_write: Arc<Mutex<Vec<u8>>>,
        pcid_from_client_read: Arc<Mutex<Vec<u8>>>,
        args: driver_interface::SubdriverArguments,
    ) {
        use driver_interface::*;

        let mut from = &pcid_from_client_read.lock().unwrap()[..];
        while let Ok(msg) = recv(&mut from) {
            let response = self.respond(msg, &args);
            let mut to = pcid_to_client_write.lock().unwrap();
            send(&mut *to, &response).unwrap();
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

static FROM_CLIENT: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
static TO_CLIENT: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));

fn handle_parsed_header(
    state: Arc<State>,
    config: &Config,
    bus_num: u8,
    dev_num: u8,
    func_num: u8,
    header: PciHeader,
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

    println!("{}", string);

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
                crate::pci::cap::CapabilitiesIter {
                    inner: crate::pci::cap::CapabilityOffsetsIter::new(header.cap_pointer(), &func),
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

                println!("PCID SPAWN {:?}", command);

                let (pcid_to_client_write, pcid_from_client_read) =
                    (Arc::clone(&TO_CLIENT), Arc::clone(&FROM_CLIENT));

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

                match command.envs(envs).spawn() {
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
            }
        }
    }
}
//
//fn setup_logging(verbosity: u8) -> Option<&'static RedoxLogger> {
//    let log_level = match verbosity {
//        0 => log::LevelFilter::Info,
//        1 => log::LevelFilter::Debug,
//        _ => log::LevelFilter::Trace,
//    };
//    let mut logger = RedoxLogger::new()
//        .with_output(
//            OutputBuilder::stderr()
//                .with_ansi_escape_codes()
//                .with_filter(log_level)
//                .flush_on_newline(true)
//                .build()
//         );
//
//    match OutputBuilder::in_redox_logging_scheme("bus", "pci", "pcid.log") {
//        Ok(b) => logger = logger.with_output(
//            b.with_filter(log::LevelFilter::Trace)
//                .flush_on_newline(true)
//                .build()
//        ),
//        Err(error) => eprintln!("pcid: failed to open pcid.log"),
//    }
//    match OutputBuilder::in_redox_logging_scheme("bus", "pci", "pcid.ansi.log") {
//        Ok(b) => logger = logger.with_output(
//            b.with_filter(log::LevelFilter::Trace)
//                .with_ansi_escape_codes()
//                .flush_on_newline(true)
//                .build()
//        ),
//        Err(error) => eprintln!("pcid: failed to open pcid.ansi.log"),
//    }
//
//    match logger.enable() {
//        Ok(logger_ref) => {
//            eprintln!("pcid: enabled logger");
//            Some(logger_ref)
//        }
//        Err(error) => {
//            eprintln!("pcid: failed to set default logger: {}", error);
//            None
//        }
//    }
//}
//
fn main() {
    let mut config = Config::default();

    let pci = Arc::new(Pci::new());

    let state = Arc::new(State {
        pci: Arc::clone(&pci),
        pcie: match Pcie::new(Arc::clone(&pci)) {
            Ok(pcie) => Some(pcie),
            Err(error) => {
                println!("Couldn't retrieve PCIe info, perhaps the kernel is not compiled with acpi? Using the PCI 3.0 configuration space instead. Error: {:?}", error);
                None
            }
        },
        threads: Mutex::new(Vec::new()),
    });

    let pci = state.preferred_cfg_access();

    println!("PCI BS/DV/FN VEND:DEVI CL.SC.IN.RV");

    let mut bus_nums = vec![0];
    let mut bus_i = 0;
    'bus: while bus_i < bus_nums.len() {
        let bus_num = bus_nums[bus_i];
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
