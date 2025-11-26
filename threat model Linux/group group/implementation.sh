#!/bin/sh

# Use stat -c for portable owner/group check
ownership=$(stat -c "%U %G" /etc/group 2>/dev/null)
if [ "$ownership" != "root root" ]; then
echo bad_group
fi
