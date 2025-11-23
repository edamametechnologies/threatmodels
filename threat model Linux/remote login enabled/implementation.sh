#!/bin/bash

LANG=C systemctl is-active ssh | grep -q 'inactive' ||
echo remote_login_enabled
