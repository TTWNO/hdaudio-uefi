# 1. `sudo rmmod -f snd_hda_intel`
# 2. `sudo systemctl start libvirtd`
# 3. Make sure KVM shit is enabled
# 4. Use this to froce SDL X11 driver, and runtime dir.
# Use Ctrl+Alt+g to jump out of the window if in focus.

#!/bin/bash

aud="0000:0f:00.4"
aud_vd="$(cat /sys/bus/pci/devices/$aud/vendor) $(cat /sys/bus/pci/devices/$aud/device)"

function bind_vfio {
	echo "$aud" > "/sys/bus/pci/devices/$aud/driver/unbind"
	echo "$aud_vd" > /sys/bus/pci/drivers/vfio-pci/new_id
}

function unbind_vfio {
	echo "$aud_vd" > "/sys/bus/pci/drivers/vfio-pci/remove_id"
	echo 1 > "/sys/bus/pci/devices/$aud/remove"
	echo 1 > "/sys/bus/pci/rescan"
}
bind_vfio

sudo -E -u root SDL_VIDEODRIVER=x11 XDG_RUNTIME_DIR=/var/ ./qemu3.sh 

unbind_vfio
