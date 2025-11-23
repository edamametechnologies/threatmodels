#!/bin/bash

ls -l /etc/group | grep -q 'root root' ||
echo bad_group
