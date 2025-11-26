#!/bin/sh

# Use stat -c for portable owner/group check
ownership=$(stat -c "%U %G" /etc/shadow 2>/dev/null)
if [ "$ownership" != "root shadow" ]; then
echo bad_group
fi
