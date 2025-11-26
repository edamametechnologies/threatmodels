#!/bin/sh

if command -v systemctl >/dev/null 2>&1; then
    LANG=C systemctl is-active nfs-kernel-server 2>/dev/null | grep -q 'inactive' || echo nfs_enabled
    LANG=C systemctl is-active smbd 2>/dev/null | grep -q 'inactive' || echo smb_enabled
elif command -v rc-service >/dev/null 2>&1; then
    rc-service nfs status >/dev/null 2>&1 && echo nfs_enabled
    rc-service samba status >/dev/null 2>&1 && echo smb_enabled
fi
