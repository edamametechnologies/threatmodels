#!/bin/sh

if command -v ufw >/dev/null 2>&1; then
    LANG=C ufw status | grep -qi 'Status: active' || echo firewall_disabled
else
    # If ufw is missing, report as disabled (remediation will attempt to install)
echo firewall_disabled
fi
