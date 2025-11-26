#!/bin/sh

if command -v apk >/dev/null 2>&1; then
    apk update >/dev/null 2>&1
    apk upgrade >/dev/null 2>&1
else
    apt update -qq > /dev/null 2>&1 || true
apt upgrade -y
fi
