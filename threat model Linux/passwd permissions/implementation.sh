#!/bin/bash

stat /etc/passwd | grep -q '(0644/-rw-r--r--)' ||
echo bad_permissions
