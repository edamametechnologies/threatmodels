#!/bin/sh

if [ ! -f /etc/security/pwquality.conf ]; then
    echo 'weak password_policy: pwquality is not in use'
elif ! grep -qvE '^\s*#|^\s*$' /etc/security/pwquality.conf; then
echo 'weak password policy: conf file uses defaults'
fi
