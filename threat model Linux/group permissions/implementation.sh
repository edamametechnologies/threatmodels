#!/bin/sh

perms=$(stat -c %a /etc/group 2>/dev/null)
if [ "$perms" != "644" ]; then
echo bad_permissions
fi
