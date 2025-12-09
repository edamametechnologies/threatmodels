#!/bin/sh

# Detect virtualization
is_virtual=""

if command -v apk >/dev/null 2>&1; then
    # Alpine: virt-what works on aarch64
    apk add virt-what util-linux >/dev/null 2>&1
    [ -n "$(virt-what 2>/dev/null)" ] && is_virtual="yes"
elif [ "$(uname -m)" = "aarch64" ]; then
    # Debian/Ubuntu aarch64: virt-what not available, use fast file-based detection
    # Check /sys/hypervisor (Xen)
    if [ -d /sys/hypervisor ]; then
        is_virtual="yes"
    # Check DMI vendor info
    elif grep -qiE "qemu|kvm|vmware|virtualbox|xen|microsoft|amazon" /sys/class/dmi/id/sys_vendor 2>/dev/null; then
        is_virtual="yes"
    # Check DMI product name
    elif grep -qiE "virtual|vm|kvm|qemu" /sys/class/dmi/id/product_name 2>/dev/null; then
        is_virtual="yes"
    # Check device tree (ARM VMs)
    elif grep -qiE "qemu|kvm|xen" /sys/firmware/devicetree/base/compatible 2>/dev/null; then
        is_virtual="yes"
    # Last resort: systemd-detect-virt with timeout
    elif command -v systemd-detect-virt >/dev/null 2>&1; then
        virt_type=$(timeout 5 systemd-detect-virt 2>/dev/null)
        [ "$virt_type" != "none" ] && [ -n "$virt_type" ] && is_virtual="yes"
    fi
else
    # Debian/Ubuntu x86_64: virt-what available
    apt install virt-what -y > /dev/null 2>&1
    [ -n "$(virt-what 2>/dev/null)" ] && is_virtual="yes"
fi

if [ -z "$is_virtual" ]; then
    root_dev=$(findmnt -n -o SOURCE /)
    swap_dev=$(swapon --show=NAME --noheadings 2>/dev/null | head -n1)
    root_parent=$(lsblk -n -o NAME,TYPE,MOUNTPOINT -p | grep " $(readlink -f "$root_dev")$" | awk '{print $1}')
    lsblk -n -o NAME,TYPE -p | grep -q "^$root_parent.*crypt$" || echo "root_encryption_disabled"
    if [ -n "$swap_dev" ]; then
        swap_parent=$(lsblk -n -o NAME,TYPE,MOUNTPOINT -p | grep " $(readlink -f "$swap_dev")$" | awk '{print $1}')
        lsblk -n -o NAME,TYPE -p | grep -q "^$swap_parent.*crypt$" || echo "swap_encryption_disabled"
    fi
fi
