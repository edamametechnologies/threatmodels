#!/bin/sh

if command -v systemctl >/dev/null 2>&1; then
    systemctl stop xrdp 2>/dev/null
    systemctl disable xrdp 2>/dev/null
elif command -v rc-service >/dev/null 2>&1; then
    rc-service xrdp stop 2>/dev/null
    rc-update del xrdp default 2>/dev/null
fi
