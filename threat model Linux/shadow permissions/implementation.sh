#!/bin/sh

# Use stat -c %a for portable permission check
perms=$(stat -c %a /etc/shadow 2>/dev/null)
if [ "$perms" != "640" ]; then
echo bad_permissions
fi
