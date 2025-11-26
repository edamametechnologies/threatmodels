#!/bin/sh

# Remove bashisms
service_active() {
  # systemd, sysvinit, openrc
  if command -v systemctl >/dev/null 2>&1; then
    systemctl is-active --quiet "$1"
  elif command -v service >/dev/null 2>&1; then
    service "$1" status >/dev/null 2>&1
  elif command -v rc-service >/dev/null 2>&1; then
    rc-service "$1" status >/dev/null 2>&1
  else
    return 1
  fi
}

has_sentinelone() {
  # SentinelOne (Linux)
  if [ -x /opt/sentinelone/bin/sentinelctl ]; then
  /opt/sentinelone/bin/sentinelctl version 2>/dev/null | grep -q . && return 0
  fi
  command -v sentinelctl >/dev/null 2>&1 && sentinelctl version 2>/dev/null | grep -q . && return 0
  return 1
}

has_crowdstrike() {
  # CrowdStrike Falcon on Linux
  service_active "falcon-sensor" && return 0
  if [ -x /opt/CrowdStrike/falconctl ]; then
     /opt/CrowdStrike/falconctl -g --version 2>/dev/null | grep -q . && return 0
  fi
  return 1
}

has_ms_defender() {
  # Microsoft Defender for Endpoint (Linux)
  command -v mdatp >/dev/null 2>&1 || return 1
  mdatp health --field real_time_protection_enabled 2>/dev/null | grep -qi "true" && return 0
  mdatp --version >/dev/null 2>&1 && return 0
  return 1
}

has_carbon_black() {
  # VMware Carbon Black Cloud sensor
  if [ -x /opt/carbonblack/psc/bin/repcli ]; then
     /opt/carbonblack/psc/bin/repcli status >/dev/null 2>&1 && return 0
  fi
  [ -d /opt/carbonblack/psc/bin ] && return 0
  return 1
}

has_cortex_xdr() {
  # Palo Alto Networks Cortex XDR / Traps
  if [ -x /opt/traps/bin/cytool ]; then
     /opt/traps/bin/cytool runtime query >/dev/null 2>&1 && return 0
  fi
  [ -d /opt/traps/bin ] && return 0
  return 1
}

has_cisco_secure_endpoint() {
  # Cisco Secure Endpoint (AMP) CLI
  if [ -x /opt/cisco/amp/bin/ampcli ]; then
     /opt/cisco/amp/bin/ampcli status >/dev/null 2>&1 && return 0
  fi
  if [ -x /opt/cisco/amp/ampcli ]; then
     /opt/cisco/amp/ampcli status >/dev/null 2>&1 && return 0
  fi
  [ -d /opt/cisco/amp ] && return 0
  return 1
}

has_sophos() {
  # Sophos Protection for Linux (SPL)
  service_active "sophos-spl.service" && return 0
  [ -d /opt/sophos-spl ] && return 0
  return 1
}

has_cylance() {
  # CylancePROTECT
  service_active "cylancesvc" && return 0
  return 1
}

has_eset() {
  # ESET Endpoint for Linux
  pgrep -x esets_daemon >/dev/null 2>&1 && return 0
  service_active "esets" && return 0
  return 1
}

if ! (
  has_sentinelone ||
  has_crowdstrike   ||
  has_ms_defender   ||
  has_carbon_black  ||
  has_cortex_xdr    ||
  has_cisco_secure_endpoint ||
  has_sophos        ||
  has_cylance       ||
  has_eset
); then
  echo "epp_disabled"
fi
