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

* Gets caught on `cmdbuff.rs:282`
  * Reads forever.
  * Writes appear to get through when `-device intel-hda,debug=5` is set.
  * Also tried with `redoxos`'s own instructions during boot, which uses `-device ich9-intel-hda,debug=5`, with no avail.
  * But reading back is never the expected value.
  * Debug shows error with `addressed non-existing codec`, which does not happen on RedoxOS's live image.
  * It could have something to do with IRQs, but I'm not entirely sure.

