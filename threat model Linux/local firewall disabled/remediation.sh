#!/bin/sh

if command -v apk >/dev/null 2>&1; then
    apk add ufw >/dev/null 2>&1
    ufw enable
else
    apt install ufw -y > /dev/null 2>&1
    ufw enable
fi
