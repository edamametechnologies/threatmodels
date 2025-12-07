#!/bin/sh

if command -v apk >/dev/null 2>&1; then
    apk update >/dev/null 2>&1
    apk add samba nfs-utils >/dev/null 2>&1
    if command -v rc-service >/dev/null 2>&1; then
        rc-service samba start
        rc-update add samba default
        rc-service nfs start
        rc-update add nfs default
    fi
else
    apt install samba -y > /dev/null 2>&1
    systemctl start smbd
    systemctl enable smbd
    apt install nfs-kernel-server -y > /dev/null 2>&1
    systemctl start nfs-kernel-server
systemctl enable nfs-kernel-server
fi
