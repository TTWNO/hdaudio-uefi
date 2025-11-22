# 1. `sudo rmmod -f snd_hda_intel`
# 2. `sudo systemctl start libvirtd`
# 3. Make sure KVM shit is enabled
# 4. Use this to froce SDL X11 driver, and runtime dir.
# Use Ctrl+Alt+g to jump out of the window if in focus.

sudo -E -u root SDL_VIDEODRIVER=x11 XDG_RUNTIME_DIR=/var/ ./qemu3.sh 
