#!/bin/sh

if command -v systemctl >/dev/null 2>&1; then
    LANG=C systemctl is-active xrdp 2>/dev/null | grep -q 'inactive' || echo rdp_enabled
elif command -v rc-service >/dev/null 2>&1; then
    rc-service xrdp status >/dev/null 2>&1 && echo rdp_enabled
fi
