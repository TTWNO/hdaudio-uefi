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
* `cargo build --target x86_64-unknown-uefi`
* `cd ..`
* `./qemu.sh`
* once inside QEMU
* `FS0:`
* `.\ihdad.efi`

