#!/bin/bash

stat /etc/fstab | grep -q '(0644/-rw-r--r--)' ||
echo bad_permissions
