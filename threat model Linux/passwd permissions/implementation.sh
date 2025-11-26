#!/bin/sh

# Use stat -c %a for portable permission check
perms=$(stat -c %a /etc/passwd 2>/dev/null)
if [ "$perms" != "644" ]; then
echo bad_permissions
fi
