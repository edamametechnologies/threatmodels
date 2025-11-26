#!/bin/sh

if command -v apk >/dev/null 2>&1; then
    # ssh usually installed, but ensure service enabled
    rc-update add sshd default 2>/dev/null
    rc-service sshd start 2>/dev/null
else
    systemctl enable ssh 2>/dev/null
    systemctl start ssh 2>/dev/null
    systemctl enable sshd 2>/dev/null
    systemctl start sshd 2>/dev/null
fi
