use std::convert::TryFrom;
use std::sync::{Mutex, Once};

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use syscall::io::{Io as _, Pio};

pub use self::bar::PciBar;
pub use self::bus::{PciBus};
pub use self::class::PciClass;
pub use self::dev::{PciDev};
pub use self::func::PciFunc;
pub use self::header::{PciHeader, PciHeaderError, PciHeaderType};



mod bar;
mod bus;
pub mod cap;
mod class;
mod dev;
pub mod func;
pub mod header;
pub mod msi;

pub trait CfgAccess {
    unsafe fn read_nolock(&self, bus: u8, dev: u8, func: u8, offset: u16) -> u32;
    unsafe fn read(&self, bus: u8, dev: u8, func: u8, offset: u16) -> u32;

    unsafe fn write_nolock(&self, bus: u8, dev: u8, func: u8, offset: u16, value: u32);
    unsafe fn write(&self, bus: u8, dev: u8, func: u8, offset: u16, value: u32);
}

pub struct Pci {
    lock: Mutex<()>,
    iopl_once: Once,
}

impl Pci {
    pub fn new() -> Self {
        Self {
            lock: Mutex::new(()),
            iopl_once: Once::new(),
        }
    }

    pub fn buses<'pci>(&'pci self) -> PciIter<'pci> {
        PciIter::new(self)
    }

    fn set_iopl() {
        // make sure that pcid is not granted io port permission unless pcie memory-mapped
        // configuration space is not available.
        println!("PCI: couldn't find or access PCIe extended configuration, and thus falling back to PCI 3.0 io ports");
        // TODO: this seems to cause an immediate exit of the program, but it may be necessray?
        //unsafe {
        //    syscall::iopl(3).expect("pcid: failed to set iopl to 3");
        //}
    }
    fn address(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
        // TODO: Find the part of pcid that uses an unaligned offset!
        //
        // assert_eq!(offset & 0xFC, offset, "pci offset is not aligned");
        //
        let offset = offset & 0xFC;

        assert_eq!(dev & 0x1F, dev, "pci device larger than 5 bits");
        assert_eq!(func & 0x7, func, "pci func larger than 3 bits");

        0x80000000
            | (u32::from(bus) << 16)
            | (u32::from(dev) << 11)
            | (u32::from(func) << 8)
            | u32::from(offset)
    }
}
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
impl CfgAccess for Pci {
    unsafe fn read_nolock(&self, bus: u8, dev: u8, func: u8, offset: u16) -> u32 {
        self.iopl_once.call_once(Self::set_iopl);

        let offset =
            u8::try_from(offset).expect("offset too large for PCI 3.0 configuration space");
        let address = Self::address(bus, dev, func, offset);

        Pio::<u32>::new(0xCF8).write(address);
        Pio::<u32>::new(0xCFC).read()
    }

    unsafe fn read(&self, bus: u8, dev: u8, func: u8, offset: u16) -> u32 {
        let _guard = self.lock.lock().unwrap();
        self.read_nolock(bus, dev, func, offset)
    }

    unsafe fn write_nolock(&self, bus: u8, dev: u8, func: u8, offset: u16, value: u32) {
        self.iopl_once.call_once(Self::set_iopl);

        let offset =
            u8::try_from(offset).expect("offset too large for PCI 3.0 configuration space");
        let address = Self::address(bus, dev, func, offset);

        Pio::<u32>::new(0xCF8).write(address);
        Pio::<u32>::new(0xCFC).write(value);
    }
    unsafe fn write(&self, bus: u8, dev: u8, func: u8, offset: u16, value: u32) {
        let _guard = self.lock.lock().unwrap();
        self.write_nolock(bus, dev, func, offset, value)
    }
}
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
impl CfgAccess for Pci {
    unsafe fn read_nolock(&self, bus: u8, dev: u8, func: u8, offset: u16) -> u32 {
        todo!("Pci::CfgAccess::read_nolock on this architecture")
    }

    unsafe fn read(&self, bus: u8, dev: u8, func: u8, offset: u16) -> u32 {
        let _guard = self.lock.lock().unwrap();
        self.read_nolock(bus, dev, func, offset)
    }

    unsafe fn write_nolock(&self, bus: u8, dev: u8, func: u8, offset: u16, value: u32) {
        todo!("Pci::CfgAccess::write_nolock on this architecture")
    }
    unsafe fn write(&self, bus: u8, dev: u8, func: u8, offset: u16, value: u32) {
        let _guard = self.lock.lock().unwrap();
        self.write_nolock(bus, dev, func, offset, value)
    }
}

pub struct PciIter<'pci> {
    pci: &'pci dyn CfgAccess,
    num: Option<u8>,
}

impl<'pci> PciIter<'pci> {
    pub fn new(pci: &'pci dyn CfgAccess) -> Self {
        PciIter { pci, num: Some(0) }
    }
}

impl<'pci> Iterator for PciIter<'pci> {
    type Item = PciBus<'pci>;
    fn next(&mut self) -> Option<Self::Item> {
        match self.num {
            Some(bus_num) => {
                let bus = PciBus {
                    pci: self.pci,
                    num: bus_num,
                };
                self.num = bus_num.checked_add(1);
                Some(bus)
            }
            None => None,
        }
    }
}
