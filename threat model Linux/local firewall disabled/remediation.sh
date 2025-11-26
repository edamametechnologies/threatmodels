#!/bin/sh

if command -v apk >/dev/null 2>&1; then
    apk update >/dev/null 2>&1
    apk add ufw >/dev/null 2>&1
    ufw enable
else
    apt update -qq > /dev/null 2>&1 || true
    apt install ufw -y > /dev/null 2>&1
ufw enable
fi
