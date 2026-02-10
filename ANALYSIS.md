# HD Audio UEFI Driver: Real Hardware Failure Analysis

Comparison of `hdaudio-uefi` against FreeBSD's `hdac.c` driver, with specific
attention to Framework 13 AMD boards.

## Table of Contents

1. [Root Cause Summary](#root-cause-summary)
2. [Critical Issues (Will Cause Hard Resets)](#critical-issues)
3. [Serious Issues (Will Cause Hangs or Malfunction)](#serious-issues)
4. [Framework 13 AMD Specifics](#framework-13-amd-specifics)
5. [Improvement Roadmap](#improvement-roadmap)

---

## Root Cause Summary

The driver has **six critical issues** that individually or together will cause
hard resets/freezes on real hardware. They work in QEMU because QEMU's emulated
HDA controller is far more tolerant of protocol violations. Listed in order of
most-likely-to-cause-a-hard-reset:

| # | Issue | Severity | File |
|---|-------|----------|------|
| 1 | **Non-volatile MMIO access** | FATAL | `io.rs` |
| 2 | **No timing delays in init sequence** | FATAL | `device.rs` |
| 3 | **Missing PCIe SNOOP configuration** | FATAL on AMD | `main.rs` |
| 4 | **No stream reset before configuration** | CRITICAL | `device.rs` |
| 5 | **CORBRP reset protocol wrong** | CRITICAL | `cmdbuff.rs` |
| 6 | **DMA buffers may not be DMA-safe** | CRITICAL | `stream.rs` |

---

## Critical Issues

### 1. MMIO Reads/Writes Are Not Volatile (`io.rs:39-53`)

**This is the single most likely cause of hard resets on real hardware.**

Current code:
```rust
fn read(&self) -> T {
    unsafe { self.value.assume_init() }
}
fn write(&mut self, value: T) {
    unsafe { *self = Mmio::from(value); }
}
```

`assume_init()` performs a regular memory read. For memory-mapped hardware
registers, the compiler is free to:
- **Optimize away reads** if it believes the value hasn't changed
- **Reorder reads and writes** relative to each other
- **Cache values in registers** instead of re-reading from hardware

On real hardware, every register read MUST hit the physical device, and writes
MUST happen in the exact order specified. QEMU tolerates this because its
emulation layer intercepts all memory accesses regardless.

**FreeBSD equivalent**: Uses `bus_space_read_4()` / `bus_space_write_4()` which
are volatile, ordered memory accesses.

**Fix**: Use `core::ptr::read_volatile` / `core::ptr::write_volatile`:
```rust
fn read(&self) -> T {
    unsafe { core::ptr::read_volatile(self.value.as_ptr()) }
}
fn write(&mut self, value: T) {
    unsafe { core::ptr::write_volatile(self.value.as_mut_ptr(), value) }
}
```

Additionally, a compiler fence (`core::sync::atomic::compiler_fence`) should be
inserted around sequences of register writes that must be ordered (e.g., writing
CORBLBASE before CORBUBASE).

---

### 2. No Timing Delays During Initialization (`device.rs`)

The HDA spec (section 4.3) mandates specific timing requirements. The FreeBSD
driver implements all of them. This driver implements **none**.

#### 2a. Controller Reset (`device.rs:662-696`)

Current code does a tight busy-loop with no delays:
```rust
self.regs.gctl.writef(CRST, false);
loop { if !self.regs.gctl.readf(CRST) { break; } }  // no delay
self.regs.gctl.writef(CRST, true);
loop { if self.regs.gctl.readf(CRST) { break; } }   // no delay
```

FreeBSD `hdac_reset()`:
```c
// Clear CRST, poll with 10us delays, max 10000 iterations
HDAC_WRITE_4(&sc->mem, HDAC_GCTL, gctl & ~HDAC_GCTL_CRST);
do {
    gctl = HDAC_READ_4(&sc->mem, HDAC_GCTL);
    if (!(gctl & HDAC_GCTL_CRST)) break;
    DELAY(10);                                // <-- 10us per poll
} while (--count);

DELAY(100);                                   // <-- 100us mandatory after reset

// Set CRST, poll with 10us delays
HDAC_WRITE_4(&sc->mem, HDAC_GCTL, gctl | HDAC_GCTL_CRST);
do {
    gctl = HDAC_READ_4(&sc->mem, HDAC_GCTL);
    if (gctl & HDAC_GCTL_CRST) break;
    DELAY(10);                                // <-- 10us per poll
} while (--count);

DELAY(1000);                                  // <-- 1ms for codec discovery
```

Key missing delays:
- **100us between CRST clear and set** (spec minimum)
- **10us between each poll iteration** (prevent bus flooding)
- **1000us (1ms) after CRST set** for codec link enumeration (spec says minimum 521us)

Without these, the driver reads STATESTS before codecs have had time to announce
themselves, and starts sending CORB commands before the controller is fully
initialized.

#### 2b. CORB/RIRB Response Polling (`cmdbuff.rs:282`)

```rust
while (self.regs.rirbwp.read() & 0xff) == (self.rirb_rp & 0xff) {}
```

No timeout, no delay. On real hardware, if a codec doesn't respond (wrong
address, codec in reset, etc.), this hangs forever. FreeBSD uses a 10000-
iteration timeout with 10us delays between polls.

#### 2c. Stream Start Polling (`device.rs:570-572`)

```rust
while output.control() & (1 << 1) == 0 {}
```

Same issue: no timeout, no delay.

**Fix**: Implement a `delay_us()` function using UEFI boot services (`Stall()`),
ACPI PM timer, or TSC. Add delays at every poll point.

---

### 3. Missing PCIe SNOOP Configuration (`main.rs`)

**This is critical for AMD hardware (including Framework 13).**

The current driver only sets PCI command register bits 0-2:
```rust
data |= 7; // I/O Space, Memory Space, Bus Master
pci.write(bus_num, dev_num, func_num, 0x04, data);
```

FreeBSD does much more:

**a) Intel TCSEL (Traffic Class Select):**
```c
v = pci_read_config(dev, 0x44, 1);
pci_write_config(dev, 0x44, v & 0xf8, 1);  // Set TC0
```
This ensures HDA traffic uses the correct PCI Express traffic class.

**b) PCIe Snoop enable (AMD/ATI specific, reg 0x42):**
```c
static const struct {
    uint16_t vendor; uint8_t reg; uint8_t mask; uint8_t enable;
} hdac_pcie_snoop[] = {
    { INTEL_VENDORID,  0x00, 0x00, 0x00 },  // Intel: no-op (built-in)
    { ATI_VENDORID,    0x42, 0xf8, 0x02 },  // ATI: reg 0x42, enable bit 1
    { AMD_VENDORID,    0x42, 0xf8, 0x02 },  // AMD: reg 0x42, enable bit 1
    { NVIDIA_VENDORID, 0x4e, 0xf0, 0x0f },  // Nvidia: reg 0x4e
};
```

For AMD (vendor 0x1022), this writes to PCI config register 0x42 to enable PCIe
snooping. Without this, DMA transfers between the HDA controller and system
memory are **not cache-coherent**. The CPU may read stale data from its cache
instead of the actual DMA buffer contents, or the controller may read stale
data. This can cause:
- CORB commands never being seen by the controller
- RIRB responses never being seen by the driver
- Stream buffer data corruption
- **Hard system resets** when the controller reads garbage DMA descriptors

**c) DMA Memory Allocation Mode:**

When snoop is not available, FreeBSD falls back to uncacheable DMA
(`HDAC_F_DMA_NOCACHE`). The current driver uses `alloc_zeroed()` which returns
normal cacheable memory, unsuitable for DMA on hardware without snooping.

**Fix**: After detecting vendor ID:
- For Intel (0x8086): Write TCSEL register at PCI config offset 0x44
- For AMD (0x1022): Enable snoop at PCI config register 0x42
- If snoop fails: Allocate all DMA buffers as uncacheable memory via UEFI
  `AllocatePages()` with `EfiRuntimeServicesData` or manual page table
  manipulation

---

### 4. No Stream Reset Before Configuration (`device.rs:505-567`)

The driver configures and starts streams without first resetting them:
```rust
output.set_address(self.buff_desc_phys);
output.set_pcm_format(...);
output.set_cyclic_buffer_length(...);
output.run();  // Start without reset!
```

FreeBSD always resets streams before configuration (`hdac_stream_reset()`):
```c
// 1. Set SRST bit
ctl |= HDAC_SDCTL_SRST;
HDAC_WRITE_1(&sc->mem, off + HDAC_SDCTL0, ctl);
// 2. Wait for SRST to be acknowledged (up to 10ms)
do { ... DELAY(10); } while (--to);
// 3. Clear SRST bit
ctl &= ~HDAC_SDCTL_SRST;
HDAC_WRITE_1(&sc->mem, off + HDAC_SDCTL0, ctl);
// 4. Wait for SRST to clear (up to 10ms)
do { ... DELAY(10); } while (--to);
```

On real hardware, streams may be in an undefined state from firmware
initialization (UEFI firmware often initializes audio for boot sounds). Starting
a stream that's already partially configured can cause DMA to random memory
addresses, causing immediate hard resets.

**Fix**: Add a `stream_reset()` function that follows the spec:
1. Set SRST bit in stream descriptor control register
2. Poll until SRST reads back as 1 (with timeout + delays)
3. Clear SRST bit
4. Poll until SRST reads back as 0 (with timeout + delays)
5. Then proceed with stream configuration

---

### 5. CORBRP Reset Protocol Is Wrong (`cmdbuff.rs:143-173`)

Current code:
```rust
// This will loop forever in virtualbox
// so we just skip it for everything
self.regs.corbrp.writef(CORBRPRST, true);
// ... no wait, no clear
```

FreeBSD `hdac_corb_init()`:
```c
HDAC_WRITE_2(&sc->mem, HDAC_CORBRP, HDAC_CORBRP_CORBRPRST);
/*
 * The HDA specification indicates that the CORBRPRST bit will always
 * read as zero. Unfortunately, it seems that at least the 82801G
 * doesn't reset the bit to zero, which stalls the corb engine.
 * manually reset the bit to zero before continuing.
 */
HDAC_WRITE_2(&sc->mem, HDAC_CORBRP, 0x0);
```

The FreeBSD approach: write the reset bit, then **immediately write 0** to clear
it. Don't bother polling for the bit to set (the spec says it reads as 0, and
some hardware is buggy about it).

**Fix**: Set CORBRPRST, then immediately clear it:
```rust
self.regs.corbrp.write(CORBRPRST);
// Small delay
self.regs.corbrp.write(0);
```

---

### 6. DMA Buffers Not DMA-Safe (`stream.rs:302-303`)

```rust
let size = block_length + block_count;  // BUG: should be block_length * block_count
let layout = Layout::from_size_align(size, 4096).unwrap();
let ptr: *mut u8 = unsafe { alloc(layout) };
```

Two problems:
- **Size calculation is wrong**: `+` instead of `*`. Allocates 2080 bytes
  instead of 65536.
- **Memory may not be DMA-safe**: `alloc()` returns normal heap memory.
  For DMA on real hardware, memory should be:
  - Page-aligned (4096 -- currently done)
  - Physically contiguous (not guaranteed by `alloc()` in all UEFI
    implementations)
  - Below 4GB if the controller doesn't support 64-bit DMA (check GCAP bit 0)
  - Uncacheable if PCIe snoop is not enabled

**Fix**: Use UEFI `AllocatePages()` boot service for DMA buffers, which
guarantees physically contiguous, identity-mapped memory. Fix the size
calculation.

---

### 7. FreeBSD Pre-Reset Quiesce (Missing Entirely)

Before resetting the controller, FreeBSD stops ALL DMA engines:
```c
// Stop all Streams DMA engine
for (i = 0; i < sc->num_iss; i++)
    HDAC_WRITE_4(&sc->mem, HDAC_ISDCTL(sc, i), 0x0);
for (i = 0; i < sc->num_oss; i++)
    HDAC_WRITE_4(&sc->mem, HDAC_OSDCTL(sc, i), 0x0);
for (i = 0; i < sc->num_bss; i++)
    HDAC_WRITE_4(&sc->mem, HDAC_BSDCTL(sc, i), 0x0);

// Stop Control DMA engines
HDAC_WRITE_1(&sc->mem, HDAC_CORBCTL, 0x0);
HDAC_WRITE_1(&sc->mem, HDAC_RIRBCTL, 0x0);

// Reset DMA position buffer
HDAC_WRITE_4(&sc->mem, HDAC_DPIBLBASE, 0x0);
HDAC_WRITE_4(&sc->mem, HDAC_DPIBUBASE, 0x0);
```

The current driver goes straight to GCTL CRST without stopping anything first.
If firmware left streams running (common on real hardware), resetting the
controller while DMA is active can cause the controller to DMA into
random/stale addresses during the reset window.

---

## Serious Issues

### 8. Immediate Command Interface Inverted (`device.rs:221-225`)

```rust
let use_immediate_command_interface = match self.vend_prod {
    0x8086_2668 => false,   // VirtualBox: DON'T use immediate
    _ => true,              // Everything else: USE immediate
};
```

This means the driver uses the **Immediate Command Interface** for all real
hardware, and CORB/RIRB only for VirtualBox. The Immediate Command Interface is
a simpler single-command interface that:
- Is **not supported by all controllers** (especially newer ones)
- Has **no DMA** -- it's polled I/O
- Is intended for BIOS/firmware use, not OS drivers
- May not work on AMD controllers at all

FreeBSD uses CORB/RIRB exclusively for all real hardware.

**Fix**: Invert the logic. Use CORB/RIRB for all hardware. Only fall back to
immediate command interface if CORB/RIRB fails or for known-broken controllers.

---

### 9. Hardcoded Widget Skip (`device.rs:363-366`)

```rust
if afg_start + j == 0x22 {
    println!("SKIP!");
    continue;
}
```

Widget 0x22 is skipped unconditionally. This is presumably a workaround for a
crash on a specific codec, but it will break codecs where widget 0x22 is a valid
and important widget (e.g., a mixer or selector needed in the audio path).

**Fix**: Remove the hardcoded skip. If a specific widget causes issues, add
proper error handling in `read_node()` so a bad widget response doesn't crash
the driver.

---

### 10. StreamBuffer Drop Uses Wrong Size (`stream.rs:363-375`)

The `Drop` implementation deallocates with `block_len * block_cnt`, but the
allocation used `block_length + block_count`. This is a use-after-free /
double-free waiting to happen, and is likely related to the "Vec drop crashes"
mentioned in CLAUDE.md.

---

## Framework 13 AMD Specifics

### Hardware Details

| Component | Old (Ryzen 7040) | New (Ryzen AI 300) |
|-----------|------------------|--------------------|
| APU | AMD Phoenix (Ryzen 7840U) | AMD Strix Point |
| HDA Controller | AMD ACP/AZ (PCI 1022:15E3) | AMD ACP/AZ |
| Audio Codec | Realtek ALC295 | Realtek ALC295 |
| Subsystem | 32AC:0002 | 32AC:0012 |

### Linux Quirks for Framework + ALC295

The Linux `patch_realtek.c` contains specific Framework entries:

```c
SND_PCI_QUIRK(0x32AC, 0x0002, "Framework Laptop 13 (AMD)",
    ALC269_FIXUP_HEADSET_MODE_NO_HP_MIC),
```

Key fixups applied:
- **ALC269_FIXUP_HEADSET_MODE_NO_HP_MIC**: Configures headset jack for combo
  headset detection without HP mic
- **Pin configuration overrides**: Specific pin default values for the Framework
  board layout
- **COEF writes**: Codec-specific coefficient register writes for proper
  amplifier biasing

### AMD-Specific Requirements for This Driver

1. **PCIe Snoop (PCI reg 0x42)**: MUST enable bit 1 for AMD vendor (0x1022).
   Without this, all DMA is broken.

2. **GCAP 64-bit check**: AMD Phoenix controllers support 64-bit DMA. Check
   GCAP bit 0 and use 64-bit addresses if supported.

3. **Reset timing**: AMD controllers may need longer codec discovery delays
   (some reports of 2ms+ needed instead of spec-minimum 521us).

4. **CORB/RIRB over Immediate Command**: AMD controllers may not support the
   Immediate Command Interface. MUST use CORB/RIRB.

5. **No TCSEL**: TCSEL register (0x44) is Intel-specific. Do NOT write it on
   AMD controllers.

### Realtek ALC295 Codec Specifics

The ALC295 is a common Realtek codec with these notable features:
- Supports combo headset jack (CTIA/OMTP)
- Has EAPD (External Amplifier Power Down) control
- Requires specific power sequencing
- Has hidden "COEF" registers (index/data pair at NID 0x20) for internal configuration
- Jack detection uses pin sense (verb 0xF09)

For Framework boards specifically, the Linux driver applies these ALC295 fixups:
- Headset mode configuration
- Mic detection calibration
- Specific pin widget configuration defaults

For basic audio output (speaker), the driver needs to:
1. Find the speaker output pin (default device = Speaker)
2. Trace path to DAC
3. Enable EAPD on the pin
4. Configure amplifier gains correctly (the ALC295 has specific gain ranges)

---

## Improvement Roadmap

### Phase 1: Make It Not Crash (Required for any real hardware)

These changes are all prerequisites for the driver to work on any real hardware,
not just QEMU:

1. **Fix `Mmio<T>` to use volatile access** (`io.rs`)
   - Replace `assume_init()` with `read_volatile()`
   - Replace `*self = Mmio::from(value)` with `write_volatile()`
   - This is the single highest-impact change

2. **Add timing delays** (`device.rs`, `cmdbuff.rs`)
   - Implement a `delay_us()` using UEFI `BootServices::stall()` or ACPI PM
     timer or TSC-based busy-wait
   - Add 10us delays in all poll loops
   - Add 100us delay after CRST clear
   - Add 1000us delay after CRST set (codec discovery)
   - Add timeouts (max iterations) to ALL poll loops

3. **Fix CORBRP reset protocol** (`cmdbuff.rs`)
   - Write CORBRPRST, then immediately write 0
   - Follow FreeBSD's approach

4. **Use CORB/RIRB for all hardware** (`device.rs`)
   - Invert the immediate command interface logic
   - Default to CORB/RIRB; only use immediate as fallback

5. **Add pre-reset quiesce** (`device.rs`)
   - Stop all stream DMA engines before GCTL reset
   - Stop CORB and RIRB DMA before reset
   - Clear DMA position buffer registers

6. **Add stream reset** (`stream.rs` / `device.rs`)
   - Implement stream reset (SRST set, wait, clear, wait)
   - Call it before any stream configuration

7. **Fix StreamBuffer size calculation** (`stream.rs:302`)
   - Change `block_length + block_count` to `block_length * block_count`

### Phase 2: AMD/Framework Support

8. **Add PCIe snoop configuration** (`main.rs`)
   - Detect vendor from PCI config
   - For AMD (0x1022): Write PCI config reg 0x42 with snoop enable
   - For Intel (0x8086): Write TCSEL reg 0x44
   - If snoop fails: fall back to uncacheable DMA memory

9. **Use UEFI boot services for DMA allocation**
   - Replace `alloc_zeroed()` with UEFI `AllocatePages()`
   - This guarantees physically contiguous, identity-mapped memory
   - If no snoop: set memory type to uncacheable via page tables or use
     `EfiRuntimeServicesData` memory type

10. **Check GCAP for 64-bit support**
    - Read GCAP bit 0
    - If not set, ensure all DMA addresses are below 4GB

### Phase 3: Robustness

11. **Add command timeout and retry** (`cmdbuff.rs`)
    - Max 10000 iterations with 10us delay for RIRB response
    - Return error on timeout instead of hanging
    - Retry commands up to 3 times on timeout

12. **Remove hardcoded widget 0x22 skip** (`device.rs`)
    - Add proper error handling in `read_node()` instead

13. **Add error recovery path**
    - If codec enumeration fails, try re-reset
    - If stream start fails, reset stream and retry
    - Graceful error returns instead of `unwrap()` / `expect()`

### Phase 4: Framework-Specific Polish

14. **Add ALC295 codec quirks**
    - Headset jack detection
    - COEF register initialization
    - Proper pin configuration for Framework board layout

15. **Add subsystem ID detection**
    - Read PCI subsystem vendor (0x32AC for Framework)
    - Apply board-specific pin configs and quirks

### Testing Strategy

Test each phase independently:
- **Phase 1**: Should make QEMU still work and stop hard resets on real hardware
- **Phase 2**: Should make AMD controllers initialize (may not produce sound yet)
- **Phase 3**: Should make the driver resilient to codec issues
- **Phase 4**: Should produce actual audio on Framework 13 AMD

For each change, test on:
1. QEMU with `ich9-intel-hda` + `hda-duplex` (regression test)
2. Real hardware with serial console or UEFI debug output
3. Framework 13 AMD specifically

---

## Quick Reference: FreeBSD vs Current Driver

| Operation | FreeBSD `hdac.c` | Current `hdaudio-uefi` |
|-----------|-------------------|------------------------|
| Register access | `bus_space_{read,write}` (volatile) | `assume_init()` / `Mmio::from()` (non-volatile) |
| Reset delay | 100us + 1000us codec discovery | None |
| Poll delay | 10us per iteration | None (tight loop) |
| Poll timeout | 10000 iterations | None or 10000 (no delay) |
| Pre-reset cleanup | Stop all DMA, clear position buffer | None |
| CORBRP reset | Write reset, then write 0 | Write reset only (skip) |
| Stream reset | Full SRST set/clear protocol | None |
| Command interface | CORB/RIRB always | Immediate command (wrong) |
| PCIe snoop | Vendor-specific config | Not implemented |
| DMA memory | `bus_dma_tag_create` (coherent) | `alloc_zeroed()` (cacheable heap) |
| Error handling | Timeouts, error codes, recovery | `unwrap()` / infinite loops |
| AMD support | Snoop reg 0x42, proper DMA | None |
