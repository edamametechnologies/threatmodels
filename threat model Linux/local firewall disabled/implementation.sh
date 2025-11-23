#!/bin/bash

LANG=C ufw status | grep -qi 'Status: active' ||
echo firewall_disabled
