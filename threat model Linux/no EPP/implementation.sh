#!/bin/bash

set -euo pipefail

service_active() {
  # systemd or sysvinit
  if command -v systemctl >/dev/null 2>&1; then
    systemctl is-active --quiet "$1"
  elif command -v service >/dev/null 2>&1; then
    service "$1" status >/dev/null 2>&1
  else
    return 1
  fi
}

has_sentinelone() {
  # SentinelOne (Linux)
  # CLI path is typically /opt/sentinelone/bin/sentinelctl
  /opt/sentinelone/bin/sentinelctl version 2>/dev/null | grep -q . && return 0
  command -v sentinelctl >/dev/null 2>&1 && sentinelctl version 2>/dev/null | grep -q . && return 0
  return 1
}

has_crowdstrike() {
  # CrowdStrike Falcon on Linux (service: falcon-sensor; CLI: /opt/CrowdStrike/falconctl)
  service_active "falcon-sensor" && return 0
  [[ -x /opt/CrowdStrike/falconctl ]] && /opt/CrowdStrike/falconctl -g --version 2>/dev/null | grep -q . && return 0
  return 1
}

has_ms_defender() {
  # Microsoft Defender for Endpoint (Linux)
  command -v mdatp >/dev/null 2>&1 || return 1
  mdatp health --field real_time_protection_enabled 2>/dev/null | grep -qi "true" && return 0
  # If the health field isn't available, consider presence of the binary as a weak signal:
  mdatp --version >/dev/null 2>&1 && return 0
  return 1
}

has_carbon_black() {
  # VMware Carbon Black Cloud sensor (RepCLI present under /opt/carbonblack/psc/bin/)
  [[ -x /opt/carbonblack/psc/bin/repcli ]] && /opt/carbonblack/psc/bin/repcli status >/dev/null 2>&1 && return 0
  [[ -d /opt/carbonblack/psc/bin ]] && return 0
  return 1
}

has_cortex_xdr() {
  # Palo Alto Networks Cortex XDR / Traps (cytool at /opt/traps/bin/cytool)
  [[ -x /opt/traps/bin/cytool ]] && /opt/traps/bin/cytool runtime query >/dev/null 2>&1 && return 0
  [[ -d /opt/traps/bin ]] && return 0
  return 1
}

has_cisco_secure_endpoint() {
  # Cisco Secure Endpoint (AMP) CLI
  [[ -x /opt/cisco/amp/bin/ampcli ]] && /opt/cisco/amp/bin/ampcli status >/dev/null 2>&1 && return 0
  [[ -x /opt/cisco/amp/ampcli ]] && /opt/cisco/amp/ampcli status >/dev/null 2>&1 && return 0
  [[ -d /opt/cisco/amp ]] && return 0
  return 1
}

has_sophos() {
  # Sophos Protection for Linux (SPL) installs under /opt/sophos-spl and runs sophos-spl.service
  service_active "sophos-spl.service" && return 0
  [[ -d /opt/sophos-spl ]] && return 0
  return 1
}

has_cylance() {
  # CylancePROTECT (Linux service: cylancesvc)
  service_active "cylancesvc" && return 0
  return 1
}

has_eset() {
  # ESET Endpoint for Linux (daemon: esets_daemon / service: esets.service)
  pgrep -x esets_daemon >/dev/null 2>&1 && return 0
  service_active "esets" && return 0
  return 1
}

if ! (
  has_sentinelone ||      # your original vendor
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
