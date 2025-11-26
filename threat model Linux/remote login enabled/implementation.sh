#!/bin/sh

if command -v systemctl >/dev/null 2>&1; then
    # Check both ssh and sshd service names
    if LANG=C systemctl is-active ssh 2>/dev/null | grep -q 'active'; then
        echo remote_login_enabled
    elif LANG=C systemctl is-active sshd 2>/dev/null | grep -q 'active'; then
        echo remote_login_enabled
    fi
elif command -v rc-service >/dev/null 2>&1; then
    # Alpine typically uses sshd
    if rc-service sshd status >/dev/null 2>&1; then
        echo remote_login_enabled
    elif rc-service ssh status >/dev/null 2>&1; then
echo remote_login_enabled
    fi
fi
