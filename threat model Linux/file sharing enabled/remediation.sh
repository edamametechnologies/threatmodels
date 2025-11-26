#!/bin/sh

if command -v systemctl >/dev/null 2>&1; then
    systemctl stop smbd && systemctl disable smbd
    systemctl stop nfs-kernel-server && systemctl disable nfs-kernel-server
elif command -v rc-service >/dev/null 2>&1; then
    rc-service samba stop 2>/dev/null
    rc-update del samba default 2>/dev/null
    rc-service nfs stop 2>/dev/null
    rc-update del nfs default 2>/dev/null
fi
