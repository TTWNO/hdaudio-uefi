qemu-system-x86_64 -enable-kvm -bios /usr/share/ovmf/x64/OVMF.fd -nodefaults -display gtk -vga std -device intel-hda  -drive format=raw,file=fat:rw:./hdaudio/target/x86_64-unknown-uefi/debug/
