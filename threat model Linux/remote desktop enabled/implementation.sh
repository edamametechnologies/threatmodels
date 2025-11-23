#!/bin/bash

LANG=C systemctl is-active xrdp 2>/dev/null | grep -q 'inactive' ||
echo rdp_enabled
