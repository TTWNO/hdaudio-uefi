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
	* Unknown how to fix.


