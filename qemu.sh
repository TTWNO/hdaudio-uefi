qemu-system-x86_64 -enable-kvm -bios /usr/share/ovmf/x64/OVMF.fd -nodefaults -display gtk -vga std -device ich9-intel-hda,debug=5 -device hda-duplex -drive format=raw,file=fat:rw:./hdaudio/target/x86_64-unknown-uefi/debug/ -display sdl -vga none -device virtio-vga,xres=800,yres=600 >& log
