# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A port of the RedoxOS Intel HD Audio driver to pure Rust targeting UEFI. The goal is to progressively move from nightly Rust with std to `no_std` and eventually `no_alloc`. The binary name is `ihdad.efi`.

## Build & Run

```bash
# Build (requires nightly Rust)
cd hdaudio && cargo +nightly build --target x86_64-unknown-uefi

# Run in QEMU (from repo root, after building)
./qemu.sh

# Inside QEMU EFI shell:
#   FS0:
#   .\ihdad.efi
```

QEMU scripts: `qemu.sh` (basic), `qemu2.sh` (Pipewire audio backend), `qemu3.sh` (CPU passthrough + Q35), `qemu4.sh` (VFIO GPU passthrough for real hardware audio device). All require OVMF UEFI firmware and KVM.

## Architecture

Two-tier driver architecture with PCI discovery feeding into HD Audio control:

**PCI subsystem** (`hdaudio/src/pcid/`): Scans PCI bus hierarchy, matches devices against `config.toml` (class=4/subclass=3 for audio), enumerates capabilities, configures BARs and MSI/MSI-X interrupts. Entry point is `pcid/main.rs`. Uses `CfgAccess` trait for PCI config space abstraction, with PCIe MMIO implementation in `pcid/pcie/`.

**HD Audio driver** (`hdaudio/src/hda/`): Controls Intel HDA controller hardware. Key components:
- `device.rs` — Core `IntelHDA` struct: controller reset, codec enumeration, widget tree traversal, audio path configuration
- `cmdbuff.rs` — CORB/RIRB ring buffer command protocol for host↔codec communication
- `stream.rs` — Audio stream descriptors, sample rate/format definitions, DMA buffer descriptor lists
- `io.rs` — `Mmio<T>` generic struct for type-safe memory-mapped register access
- `common.rs` — HDA enums: widget types, default devices, port connectivity, locations
- `node.rs` — HDA node/widget structures representing codec topology

**Shared library** (`common/`): `PhysBox` RAII wrapper for physical memory / DMA allocations, physical-to-virtual memory mapping.

**IPC**: PCI and HDA subsystems communicate via crossbeam channels (`SubdriverArguments` carries BAR addresses and IRQ info from PCI to HDA).

## Key Technical Constraints

- `HashMap` crashes in UEFI — use `BTreeMap` instead
- Direct memory access required (not memory-mapped I/O wrappers) for register writes to work
- QEMU needs `-device ich9-intel-hda -device hda-duplex` for RIRB write pointer updates
- `Drop` implementations on certain types (e.g., `Vec<(u8, u16)>` in `configure()`) cause crashes — active investigation area
- Lots of `unsafe` code for hardware register access; be careful with pointer arithmetic and alignment

## Crate Structure

Workspace has two crates:
- `hdaudio/` — Main binary (`ihdad`), contains both PCI and HDA modules
- `common/` — Shared library for DMA/physical memory abstractions
