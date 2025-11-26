#!/bin/sh

if command -v systemctl >/dev/null 2>&1; then
    systemctl stop ssh 2>/dev/null
    systemctl disable ssh 2>/dev/null
    systemctl stop sshd 2>/dev/null
    systemctl disable sshd 2>/dev/null
elif command -v rc-service >/dev/null 2>&1; then
    rc-service sshd stop 2>/dev/null
    rc-update del sshd default 2>/dev/null
    rc-service ssh stop 2>/dev/null
    rc-update del ssh default 2>/dev/null
fi
