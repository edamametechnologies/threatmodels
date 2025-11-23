#!/bin/bash

LANG=C systemctl is-active nfs-kernel-server 2>/dev/null | grep -q 'inactive' ||
echo nfs_enabled;
LANG=C systemctl is-active smbd 2>/dev/null | grep -q 'inactive' ||
echo smb_enabled
