#!/bin/sh

if command -v apk >/dev/null 2>&1; then
    apk add virt-what util-linux >/dev/null 2>&1
else
    apt install virt-what -y > /dev/null 2>&1
fi

if [ -z "$(virt-what)" ]; then
    root_dev=$(findmnt -n -o SOURCE /)
    swap_dev=$(swapon --show=NAME --noheadings 2>/dev/null | head -n1)
    root_parent=$(lsblk -n -o NAME,TYPE,MOUNTPOINT -p | grep " $(readlink -f "$root_dev")$" | awk '{print $1}')
    lsblk -n -o NAME,TYPE -p | grep -q "^$root_parent.*crypt$" || echo "root_encryption_disabled"
    if [ -n "$swap_dev" ]; then
        swap_parent=$(lsblk -n -o NAME,TYPE,MOUNTPOINT -p | grep " $(readlink -f "$swap_dev")$" | awk '{print $1}')
        lsblk -n -o NAME,TYPE -p | grep -q "^$swap_parent.*crypt$" || echo "swap_encryption_disabled"
    fi
fi
