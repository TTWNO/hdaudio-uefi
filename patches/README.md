# HD Audio UEFI Driver Patches

12 patches addressing all issues from `ANALYSIS.md`, organized into 3 phases.

---

## Quick Start

```bash
# From the repo root (hdaudio-uefi/):

# 1. Dry-run all patches first to check for conflicts
for f in patches/{01..12}-*.diff; do
  echo "=== Checking $f ==="
  git apply --check "$f" 2>&1 || echo "NEEDS MANUAL APPLY"
done

# 2. Apply all patches in order
for f in patches/{01..12}-*.diff; do
  echo "=== Applying $f ==="
  git apply "$f"
done

# 3. Build to verify
cd hdaudio && cargo +nightly build --target x86_64-unknown-uefi
```

---

## Applying Patches One at a Time

These are unified diffs with `a/` and `b/` prefixes, compatible with `git apply` (which strips one path component by default). Apply from the **repo root** (`hdaudio-uefi/`).

### Review a patch before applying

```bash
# Read the diff
cat patches/01-volatile-mmio.diff

# Check it applies cleanly (dry run, no changes made)
git apply --check patches/01-volatile-mmio.diff

# See what it would change, with color
git apply --stat patches/01-volatile-mmio.diff
```

### Apply a patch

```bash
git apply patches/01-volatile-mmio.diff
```

### If `git apply` rejects a patch

The diffs were hand-written to match the current source. If whitespace or context has drifted, try:

```bash
# Relax whitespace matching
git apply --whitespace=fix patches/XX-name.diff

# Relax context matching (allow fuzz)
git apply -C1 patches/XX-name.diff

# Last resort: use patch(1) which is more lenient
patch -p1 < patches/XX-name.diff
```

If a patch still fails, apply it manually -- each diff is small and self-contained. The `---`/`+++` headers show which file to edit, and the `-`/`+` lines show what to remove/add.

---

## Application Order and Dependencies

```
Phase 1: Make It Not Crash
==========================

01-volatile-mmio          (independent - apply first)
  |
02-delay-function         (independent - apply second, prereq for 03-09)
  |
  +-- 03-timing-delays-reset      (depends on 02)
  +-- 04-timing-delays-cmdbuff    (depends on 02)
  +-- 05-timing-delays-stream-start (depends on 02)
  +-- 06-corbrp-reset             (depends on 02)
  +-- 08-pre-reset-quiesce        (depends on 02)
  +-- 09-stream-reset             (depends on 02)
  |
07-corb-rirb-default      (independent of 02, but apply after 06)
10-streambuffer-size      (independent)

Phase 2: AMD/Framework Support
==============================

11-pcie-snoop             (independent)

Phase 3: Robustness
===================

12-remove-widget-skip     (independent)
```

**Hard rule**: Patch 02 must be applied before patches 03, 04, 05, 06, 08, 09 -- they all call `super::delay_us()` which patch 02 introduces.

**Recommended rule**: Apply 01 before 02, because volatile MMIO makes the delay loops actually work (without volatile, the compiler could optimize away the register reads inside the poll loops that 03-05 add).

**Everything else** is independent and can be applied in any order, but the numbered order is recommended for logical grouping.

---

## Step-by-Step Procedure

### Step 1: Patch 01 -- Volatile MMIO (`io.rs`)

**What**: Replaces `assume_init()` with `read_volatile()` and `Mmio::from()` with `write_volatile()`.

**Why first**: Every other register access in the driver flows through `Mmio<T>`. Without this, the compiler can optimize away, reorder, or cache hardware register reads/writes. All subsequent patches that add poll loops or register writes depend on this actually hitting hardware.

```bash
git apply patches/01-volatile-mmio.diff
cd hdaudio && cargo +nightly build --target x86_64-unknown-uefi && cd ..
```

**Verify**: `io.rs` lines 39-53 should now use `core::ptr::read_volatile` / `core::ptr::write_volatile`. No `assume_init` or `Mmio::from(value)` in the read/write methods.

### Step 2: Patch 02 -- Delay Function (`hda/mod.rs`)

**What**: Adds `pub fn delay_us(us: u64)` using TSC-based busy-wait.

**Why second**: Prerequisite for patches 03-09. Uses `core::arch::x86_64::_rdtsc()` with a conservative 1 GHz assumption (real CPUs are 2-4 GHz, so delays are always >= requested).

```bash
git apply patches/02-delay-function.diff
cd hdaudio && cargo +nightly build --target x86_64-unknown-uefi && cd ..
```

**Verify**: `hda/mod.rs` should have a new `pub fn delay_us(us: u64)` function between the `pub use` blocks.

### Step 3: Patch 03 -- Reset Timing (`device.rs`)

**What**: Adds delays to `reset_controller()`: 10us per poll iteration, 100us after CRST clear, 2000us for codec discovery.

```bash
git apply patches/03-timing-delays-reset.diff
```

**Verify**: `reset_controller()` should have `for _ in 0..10000` loops with `super::delay_us(10)` calls, plus standalone `super::delay_us(100)` and `super::delay_us(2000)` calls.

### Step 4: Patch 04 -- CORB/RIRB Timeouts (`cmdbuff.rs`)

**What**: Adds 10us delays and 10000-iteration timeouts to `Corb::stop()`, `Corb::send_command()`, `Rirb::read_response()`, and `ImmediateCommand::cmd()`.

```bash
git apply patches/04-timing-delays-cmdbuff.diff
```

**Verify**: All `while` loops in `cmdbuff.rs` should now be `for i in 0..10000u32` with `super::delay_us(10)` and timeout println warnings.

### Step 5: Patch 05 -- Stream Start Timeout (`device.rs`)

**What**: Replaces the infinite `while output.control() & (1 << 1) == 0 {}` with a 10000-iteration timeout loop.

```bash
git apply patches/05-timing-delays-stream-start.diff
```

**Verify**: The stream start wait around line 570 should be a `for` loop, not `while`.

### Step 6: Patch 06 -- CORBRP Reset Protocol (`cmdbuff.rs`)

**What**: Replaces the broken `reset_read_pointer()` with the FreeBSD approach: write CORBRPRST, delay 100us, write 0.

```bash
git apply patches/06-corbrp-reset.diff
```

**Verify**: `reset_read_pointer()` should be ~5 lines: write, delay, write. The old `if true { ... } else { ... }` block with its commented-out polling should be gone.

### Step 7: Patch 07 -- CORB/RIRB Default (`device.rs`)

**What**: Changes `use_immediate_command_interface` to default to `false` for all hardware. CORB/RIRB is the proper interface; Immediate Command is for BIOS use.

```bash
git apply patches/07-corb-rirb-default.diff
```

**Verify**: The match in `init()` should have `_ => false` instead of `_ => true`.

### Step 8: Patch 08 -- Pre-Reset DMA Quiesce (`device.rs`)

**What**: Adds code at the top of `reset_controller()` to stop all stream DMA engines, CORB, RIRB, and clear the DMA position buffer before touching GCTL.

```bash
git apply patches/08-pre-reset-quiesce.diff
```

**Verify**: `reset_controller()` should start with loops stopping input/output stream descriptors, then `corbctl.write(0)`, `rirbctl.write(0)`, `dplbase.write(0)`, `dpubase.write(0)`.

### Step 9: Patch 09 -- Stream Reset (`stream.rs` + `device.rs`)

**What**: Adds `StreamDescriptorRegs::reset()` (SRST set, poll, clear, poll) and calls it before stream configuration in `configure()`.

```bash
git apply patches/09-stream-reset.diff
```

**Verify**: `stream.rs` should have a new `pub fn reset(&mut self)` method. `device.rs` `configure()` should call `output.reset()` before `output.set_address(...)`.

### Step 10: Patch 10 -- Buffer Size Fix (`stream.rs`)

**What**: Changes `block_length + block_count` to `block_length * block_count` in `StreamBuffer::new()`.

```bash
git apply patches/10-streambuffer-size.diff
```

**Verify**: Line ~302 of `stream.rs` should read `let size = block_length * block_count;`. This also fixes the mismatched alloc/dealloc sizes that the `Drop` impl had.

### Step 11: Patch 11 -- PCIe Snoop (`main.rs`)

**What**: Adds vendor-specific PCIe snoop configuration after enabling bus mastering:
- Intel (0x8086): TCSEL at PCI config 0x44
- AMD (0x1022): Snoop at PCI config 0x42
- Nvidia (0x10DE): Snoop at PCI config 0x4E

```bash
git apply patches/11-pcie-snoop.diff
```

**Verify**: After the `data |= 7; pci.write(...)` block in `handle_parsed_header()`, there should be a new `match vendor_id { ... }` block.

### Step 12: Patch 12 -- Remove Widget Skip (`device.rs`)

**What**: Removes the `if afg_start + j == 0x22 { continue; }` hardcoded skip.

```bash
git apply patches/12-remove-widget-skip.diff
```

**Verify**: The `enumerate()` method should go straight from `print!("TRY WIDGET...");` to `let mut widget = self.read_node(...)` with no conditional skip.

---

## Final Build and Test

```bash
cd hdaudio && cargo +nightly build --target x86_64-unknown-uefi && cd ..

# Smoke test in QEMU (regression test)
./qemu.sh
# In EFI shell: FS0:  then  .\ihdad.efi

# Test with Q35 chipset (closer to real hardware)
./qemu3.sh
```

### What to look for in QEMU output

After all patches, you should see:
- `Statests: XXXX` with a non-zero value (codecs detected)
- `Corb: XXXXXXXX` / `Rirb: XXXXXXXX` messages (CORB/RIRB working, not immediate cmd)
- No `timeout waiting for` warnings
- `Output 0 CONTROL ... STATUS ... POS ...` (stream started successfully)
- No hangs or infinite loops

### Testing on real hardware

For Framework 13 AMD specifically:
1. Patch 11 (PCIe snoop) is **mandatory** -- without it, DMA is broken
2. Patch 07 (CORB/RIRB) is **mandatory** -- AMD may not support Immediate Command
3. Use serial console or UEFI debug output to capture logs
4. If it still resets, the next areas to investigate are DMA buffer allocation (UEFI `AllocatePages` vs `alloc`) and 64-bit DMA capability checking (GCAP bit 0)
