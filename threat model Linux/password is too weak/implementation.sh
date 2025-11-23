#!/bin/bash

[ ! -f /etc/security/pwquality.conf ] &&
echo 'weak password_policy: pwquality is not in use' ||
! grep -qvE '^\s*#|^\s*$' /etc/security/pwquality.conf &&
echo 'weak password policy: conf file uses defaults'
