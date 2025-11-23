#!/bin/bash

stat /etc/group | grep -q '(0644/-rw-r--r--)' ||
echo bad_permissions
