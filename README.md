# `hdaudio-uefi`

An attempt to port the RedoxOS HD Audio driver to pure Rust, with no standard library.
Currently in progress towards basic first goal of nightly Rust for x86_64 UEFI, which has part of the standard library, then work to port that to `no_std`:

* [ ] `x86_64-unknown-uefi` (nightly, with std)
* [ ] `x86_64-unknown-uefi` (stable, `no_std`)
* [ ] `x86_64-unknwon-unknown` (`no_std`, stable, possibly `no_alloc`?)

## TODO

* [ ] Re-implement original `syscall::*` interfaces from original [`redox-drivers`](https://gitlab.redox-os.org/redox-os/drivers) repo.
  * [ ] `syscall::physmap`
  * [ ] `syscall::physalloc`
  * [ ] `syscall::physfree`
  * [ ] `syscall::setrens`
  * [ ] `syscall::fmap`
  * [ ] `syscall::open`
  * [ ] `syscall::close`

## Running

* `cd hdaudio`
* `cargo +nightly build --target x86_64-unknown-uefi`
* `cd ..`
* `./qemu.sh`
* once inside QEMU
* `FS0:`
* `.\ihdad.efi`

## Current Problems

* Running on real hardware (Framework, Intel 11th Gen)
  * Program exists after returning from `IntelHDA::configure()`
  * I assume this is because something is overwriting a stack pointer or something?
  * Or maybe tthere's a bigger issue?
  * No leads so far.
  * Something interesting is that the capabilities register appears to show 0x0 on real hardware, so maybe that's related.

## Previous Problems

* [X] Could read, but not write values.
  * Fixed by using direct memory access instead of memory-mapped IO.
* [X] Could not read updates to RIRBWP address (in QEMU).
  * Fixed in QEMU by adding the: `-device ich9-intel-hda -device hda-duplex`
* [X] Random crashes
  * Fixed by removing `syscall::*` functions and replacing with `std::` functions, where possible.
  * `HashMap -> BTreeMap`: `HashMap`s instantly crash the program.
* [ ] Leaving the `HdaDevice::configure()` function caused an instant crash.
	* This is confirmed as due to the `drop(...)` implementation of the `path` variable causing the crash. If the `drop()` is done early and explicitly, it crashes early.
	* It is not the `Vec<_>` or `(u8, u16)` drop impls that are causing this.... Is there a custom drop somewhere?
	* The value also appears to change midway through. Reading the value twice shows two different values [(0,0),(0,10)], then [(0,0),(0,0)] unsure what that is. Probably some memory magic I'm unaware of.
	* Unknown how to fix.

## Update: 2025-11-23

- Tried to get it working on Framework 13, w/ CPU (AMD Ryzen 5 7640U w/ Radeon 760M Graphics)
- Issues encountered: unable to find an output pin via `IntelHDA::find_best_output_pin`; none of them match all the conditions required.
- Tried removing the condition of "precense detection" (i.e., headphones plugged in), but this caused an instant crash.
- Unknown if crash is related to dropping vec in `IntelHDA::configure()` like before, or if this is another issue—unable to verify because I can't get laptop to work with PCI passthrough of the audio device.
- Looked at FreeBSD's implementation for inspiration, but the implementations are so different, and I already barely understand the protocal as it is.
	- It looks like framework laptops consistently have workarounds in the FreeBSD driver. So maybe there is something here that needs to be mitigatied especially for these chipsets.
	- Consider looking into which exact chipset is used, mitigation technique.
- Why not look at the Linux driver?
	- Can't, since it's GPL. This driver, as I want it to be integrated into firmware, would not be possible as GPL.
- Consider: finding an old laptop that might be compatible with `intel-ich9` edition of the codec.
- Not sure how to move forward for FW laptop.

