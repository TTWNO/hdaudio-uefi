//use syscall::io::{Io, Mmio};

use super::common::*;

// CORBCTL
const CMEIE: u8 = 1 << 0; // 1 bit
const CORBRUN: u8 = 1 << 1; // 1 bit

// CORBSIZE
const CORBSZCAP: (u8, u8) = (4, 4);
const CORBSIZE: (u8, u8) = (0, 2);

// CORBRP
const CORBRPRST: u16 = 1 << 15;

// RIRBWP
const RIRBWPRST: u16 = 1 << 15;

// RIRBCTL
const RINTCTL: u8 = 1 << 0; // 1 bit
const RIRBDMAEN: u8 = 1 << 1; // 1 bit

const CORB_OFFSET: usize = 0x00;
const RIRB_OFFSET: usize = 0x10;
const ICMD_OFFSET: usize = 0x20;

// ICS
const ICB: u16 = 1 << 0;
const IRV: u16 = 1 << 1;

// CORB and RIRB offset

const COMMAND_BUFFER_OFFSET: usize = 0x40;
const CORB_BUFF_MAX_SIZE: usize = 1024;

struct CommandBufferRegs {
    corblbase: *mut u32,
    corbubase: *mut u32,
    corbwp: *mut u16,
    corbrp: *mut u16,
    corbctl: *mut u8,
    corbsts: *mut u8,
    corbsize: *mut u8,
    rsvd5: *mut u8,

    rirblbase: *mut u32,
    rirbubase: *mut u32,
    rirbwp: *mut u16,
    rintcnt: *mut u16,
    rirbctl: *mut u8,
    rirbsts: *mut u8,
    rirbsize: *mut u8,
    rsvd6: *mut u8,
}

struct CorbRegs {
    corblbase: *mut u32,
    corbubase: *mut u32,
    corbwp: *mut u16,
    corbrp: *mut u16,
    corbctl: *mut u8,
    corbsts: *mut u8,
    corbsize: *mut u8,
    rsvd5: *mut u8,
}

struct Corb {
    regs: &'static mut CorbRegs,
    corb_base: *mut u32,
    corb_base_phys: usize,
    corb_count: usize,
}

impl Corb {
    pub fn new(regs_addr: usize, corb_buff_phys: usize, corb_buff_virt: usize) -> Corb {
        println!("regs addr {:x}", regs_addr);
        unsafe {
            Corb {
                regs: &mut *(regs_addr as *mut CorbRegs),
                corb_base: (corb_buff_virt) as *mut u32,
                corb_base_phys: corb_buff_phys,
                corb_count: 0,
            }
        }
    }
    //Intel 4.4.1.3
    pub fn init(&mut self) {
        println!("{}:{}", file!(), line!());
        self.stop();
        println!("{}:{}", file!(), line!());
        //Determine CORB and RIRB size and allocate buffer

        //3.3.24
        let corbsize_reg = self.regs.corbsize.read();
        let corbszcap = (corbsize_reg >> 4) & 0xF;

        let mut corbsize_bytes: usize = 0;
        let mut corbsize: u8 = 0;

        if (corbszcap & 4) == 4 {
            corbsize = 2;
            corbsize_bytes = 1024;

            self.corb_count = 256;
        } else if (corbszcap & 2) == 2 {
            corbsize = 1;
            corbsize_bytes = 64;

            self.corb_count = 16;
        } else if (corbszcap & 1) == 1 {
            corbsize = 0;
            corbsize_bytes = 8;

            self.corb_count = 2;
        }

        assert!(self.corb_count != 0);
        let addr = self.corb_base_phys;
        self.set_address(addr);
        self.regs.corbwp.write(0);
        self.reset_read_pointer();
    }

    pub fn start(&mut self) {
        self.regs.corbctl.writef(CORBRUN, true);
    }

    #[inline(never)]
    pub fn stop(&mut self) {
        while self.regs.corbctl.readf(CORBRUN) {
            self.regs.corbctl.write(0);
        }
    }

    pub fn set_address(&mut self, addr: usize) {
        self.regs.corblbase.write((addr & 0xFFFFFFFF) as u32);
        self.regs.corbubase.write(((addr as u64) >> 32) as u32);
    }

    pub fn reset_read_pointer(&mut self) {
        /*
         * FIRST ISSUE/PATCH
         * This will loop forever in virtualbox
         * So maybe just resetting the read pointer
         * and leaving for the specific model?
         */
        if true {
            self.regs.corbrp.writef(CORBRPRST, true);
        } else {
            // 3.3.21

            self.stop();
            // Set CORBRPRST to 1
            log::trace!("CORBRP {:X}", self.regs.corbrp.read());
            self.regs.corbrp.writef(CORBRPRST, true);
            log::trace!("CORBRP {:X}", self.regs.corbrp.read());

            // Wait for it to become 1
            while !self.regs.corbrp.readf(CORBRPRST) {
                self.regs.corbrp.writef(CORBRPRST, true);
            }
            // Clear the bit again
            self.regs.corbrp.write(0);

            // Read back the bit until zero to verify that it is cleared.

            loop {
                if !self.regs.corbrp.readf(CORBRPRST) {
                    break;
                }
                self.regs.corbrp.write(0);
            }
        }
    }

    fn send_command(&mut self, cmd: u32) {
        // wait for the commands to finish
        while (self.regs.corbwp.read() & 0xff) != (self.regs.corbrp.read() & 0xff) {}
        let write_pos: usize =
            ((self.regs.corbwp.read() as usize & 0xFF) + 1) % self.corb_count;
        unsafe {
            *self.corb_base.offset(write_pos as isize) = cmd;
        }

        self.regs.corbwp.write(write_pos as u16);

        log::trace!("Corb: {:08X}", cmd);
    }
}

struct RirbRegs {
    rirblbase: *mut u32,
    rirbubase: *mut u32,
    rirbwp: *mut u16,
    rintcnt: *mut u16,
    rirbctl: *mut u8,
    rirbsts: *mut u8,
    rirbsize: *mut u8,
    rsvd6: *mut u8,
}

struct Rirb {
    regs: &'static mut RirbRegs,
    rirb_base: *mut u64,
    rirb_base_phys: usize,
    rirb_rp: u16,
    rirb_count: usize,
}

impl Rirb {
    pub fn new(regs_addr: usize, rirb_buff_phys: usize, rirb_buff_virt: usize) -> Rirb {
        unsafe {
            Rirb {
                regs: &mut *(regs_addr as *mut RirbRegs),
                rirb_base: (rirb_buff_virt) as *mut u64,
                rirb_rp: 0,
                rirb_base_phys: rirb_buff_phys,
                rirb_count: 0,
            }
        }
    }
    //Intel 4.4.1.3
    pub fn init(&mut self) {
        self.stop();

        let rirbsize_reg = self.regs.rirbsize.read();
        let rirbszcap = (rirbsize_reg >> 4) & 0xF;

        let mut rirbsize_bytes: usize = 0;
        let mut rirbsize: u8 = 0;

        if (rirbszcap & 4) == 4 {
            rirbsize = 2;
            rirbsize_bytes = 2048;

            self.rirb_count = 256;
        } else if (rirbszcap & 2) == 2 {
            rirbsize = 1;
            rirbsize_bytes = 128;

            self.rirb_count = 8;
        } else if (rirbszcap & 1) == 1 {
            rirbsize = 0;
            rirbsize_bytes = 16;

            self.rirb_count = 2;
        }

        assert!(self.rirb_count != 0);

        let addr = self.rirb_base_phys;
        self.set_address(addr);

        self.reset_write_pointer();
        self.rirb_rp = 0;

        self.regs.rintcnt.write(1);
    }

    pub fn start(&mut self) {
        self.regs.rirbctl.writef(RIRBDMAEN | RINTCTL, true);
    }

    pub fn stop(&mut self) {
        let mut val = self.regs.rirbctl.read();
        val &= !(RIRBDMAEN);
        self.regs.rirbctl.write(val);
    }

    pub fn set_address(&mut self, addr: usize) {
        self.regs.rirblbase.write((addr & 0xFFFFFFFF) as u32);
        self.regs.rirbubase.write(((addr as u64) >> 32) as u32);
    }

    pub fn reset_write_pointer(&mut self) {
        self.regs.rirbwp.writef(RIRBWPRST, true);
    }

    fn read_response(&mut self) -> u64 {
        // wait for response
        while (self.regs.rirbwp.read() & 0xff) == (self.rirb_rp & 0xff) {}
        let read_pos: u16 = (self.rirb_rp + 1) % self.rirb_count as u16;

        let res: u64;
        unsafe {
            res = *self.rirb_base.offset(read_pos as isize);
        }
        self.rirb_rp = read_pos;
        log::trace!("Rirb: {:08X}", res);
        res
    }
}

struct ImmediateCommandRegs {
    icoi: *mut u32,
    irii: *mut u32,
    ics: *mut u16,
    rsvd7: [*mut u8; 6],
}

pub struct ImmediateCommand {
    regs: &'static mut ImmediateCommandRegs,
}

impl ImmediateCommand {
    pub fn new(regs_addr: usize) -> ImmediateCommand {
        unsafe {
            ImmediateCommand {
                regs: &mut *(regs_addr as *mut ImmediateCommandRegs),
            }
        }
    }

    pub fn cmd(&mut self, cmd: u32) -> u64 {
        // wait for ready
        while self.regs.ics.readf(ICB) {}

        // write command
        self.regs.icoi.write(cmd);

        // set ICB bit to send command
        self.regs.ics.writef(ICB, true);

        // wait for IRV bit to be set to indicate a response is latched
        while !self.regs.ics.readf(IRV) {}

        // read the result register twice, total of 8 bytes
        // highest 4 will most likely be zeros (so I've heard)
        let mut res: u64 = self.regs.irii.read() as u64;
        res |= (self.regs.irii.read() as u64) << 32;

        // clear the bit so we know when the next response comes
        self.regs.ics.writef(IRV, false);

        res
    }
}

pub struct CommandBuffer {
    // regs: &'static mut CommandBufferRegs,
    corb: Corb,
    rirb: Rirb,
    icmd: ImmediateCommand,

    corb_rirb_base_phys: usize,

    use_immediate_cmd: bool,
}

impl CommandBuffer {
    pub fn new(
        regs_addr: usize,
        cmd_buff_frame_phys: usize,
        cmd_buff_frame: usize,
    ) -> CommandBuffer {
        let corb = Corb::new(regs_addr + CORB_OFFSET, cmd_buff_frame_phys, cmd_buff_frame);
        let rirb = Rirb::new(
            regs_addr + RIRB_OFFSET,
            cmd_buff_frame_phys + CORB_BUFF_MAX_SIZE,
            cmd_buff_frame + CORB_BUFF_MAX_SIZE,
        );

        let icmd = ImmediateCommand::new(regs_addr + ICMD_OFFSET);

        let cmdbuff = CommandBuffer {
            corb: corb,
            rirb: rirb,
            icmd: icmd,

            corb_rirb_base_phys: cmd_buff_frame_phys,

            use_immediate_cmd: false,
        };

        cmdbuff
    }

    pub fn init(&mut self, use_imm_cmds: bool) {
        self.corb.init();
        self.rirb.init();
        self.set_use_imm_cmds(use_imm_cmds);
    }

    pub fn cmd12(&mut self, addr: WidgetAddr, command: u32, data: u8) -> u64 {
        let mut ncmd: u32 = 0;

        ncmd |= (addr.0 as u32 & 0x00F) << 28;
        ncmd |= (addr.1 as u32 & 0x0FF) << 20;
        ncmd |= (command & 0xFFF) << 8;
        ncmd |= (data as u32 & 0x0FF) << 0;
        self.cmd(ncmd)
    }
    pub fn cmd4(&mut self, addr: WidgetAddr, command: u32, data: u16) -> u64 {
        let mut ncmd: u32 = 0;

        ncmd |= (addr.0 as u32 & 0x000F) << 28;
        ncmd |= (addr.1 as u32 & 0x00FF) << 20;
        ncmd |= (command & 0x000F) << 16;
        ncmd |= (data as u32 & 0xFFFF) << 0;
        self.cmd(ncmd)
    }

    pub fn cmd(&mut self, cmd: u32) -> u64 {
        if self.use_immediate_cmd {
            self.cmd_imm(cmd)
        } else {
            self.cmd_buff(cmd)
        }
    }

    pub fn cmd_imm(&mut self, cmd: u32) -> u64 {
        self.icmd.cmd(cmd)
    }

    pub fn cmd_buff(&mut self, cmd: u32) -> u64 {
        self.corb.send_command(cmd);
        self.rirb.read_response()
    }

    pub fn set_use_imm_cmds(&mut self, use_imm: bool) {
        self.use_immediate_cmd = use_imm;

        if self.use_immediate_cmd {
            self.corb.stop();
            self.rirb.stop();
        } else {
            self.corb.start();
            self.rirb.start();
        }
    }
}
