#!/bin/bash

stat /etc/shadow | grep -q '(0640/-rw-r-----)' ||
echo bad_permissions
