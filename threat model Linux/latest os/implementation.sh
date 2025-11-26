#!/bin/sh

if command -v apk >/dev/null 2>&1; then
    apk update >/dev/null 2>&1
    # apk list -u lists upgradeable packages. If output is not empty, updates are available.
    if [ -n "$(apk list -u 2>/dev/null)" ]; then
echo os_outdated
    fi
else
    LANG=C apt update -qq > /dev/null 2>&1 || true
    apt list --upgradeable 2>/dev/null | grep -q 'upgradable' && echo os_outdated
fi
