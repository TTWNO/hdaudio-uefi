# `hdaudio-uefi`

An attempt to port the RedoxOS HD Audio driver to pure Rust, with no standard library.
Currently in progress towards basic first goal:

* [ ] `x86_64-unknown-uefi` (nightly, with std)
* [ ] `x86_64-unknwon-unknown` (`no_std`)

## TODO

* [ ] Re-implement original `syscall::*` interfaces from original [`redox-drivers`](https://gitlab.redox-os.org/redox-os/drivers) repo.
  * [ ] `syscall::physmap`
  * [ ] `syscall::physalloc`
  * [ ] `syscall::physfree`
  * [ ] `syscall::setrens`
  * [ ] `syscall::fmap`
  * [ ] `syscall::open`
  * [ ] `syscall::close`
