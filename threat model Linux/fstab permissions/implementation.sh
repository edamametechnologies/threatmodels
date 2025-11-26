#!/bin/sh

# Use stat -c %a for portable permission check (works on GNU and Busybox)
perms=$(stat -c %a /etc/fstab 2>/dev/null)
if [ "$perms" != "644" ]; then
echo bad_permissions
fi
