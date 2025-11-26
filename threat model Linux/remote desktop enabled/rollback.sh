#!/bin/sh

if command -v apk >/dev/null 2>&1; then
    apk update >/dev/null 2>&1
    apk add xrdp >/dev/null 2>&1
    rc-service xrdp start 2>/dev/null
    rc-update add xrdp default 2>/dev/null
else
    apt update -qq > /dev/null 2>&1 || true
    apt install xrdp -y > /dev/null 2>&1
    systemctl start xrdp
systemctl enable xrdp
fi
