#!/bin/bash

set -euo pipefail

is_proc()  { pgrep -x "$1" >/dev/null 2>&1; }
is_fproc() { pgrep -f "$1" >/dev/null 2>&1; }

has_crowdstrike() {
  # CrowdStrike Falcon (system extension + app/CLI)
  [[ -e "/Library/LaunchDaemons/com.crowdstrike.falcon.Agent.plist" ]] && return 0
  command -v systemextensionsctl >/dev/null 2>&1 && \
    systemextensionsctl list 2>/dev/null | grep -Fq "com.crowdstrike.falcon.Agent" && return 0
  [[ -x "/Applications/Falcon.app/Contents/Resources/falconctl" ]] && return 0
  return 1
}

has_carbonblack() {
  # VMware Carbon Black Cloud / EDR (daemon plist names)
  [[ -e "/Library/LaunchDaemons/com.vmware.carbonblack.cloud.daemon.plist" ]] && return 0
  [[ -e "/Library/LaunchDaemons/com.carbonblack.daemon.plist" ]] && return 0
  command -v systemextensionsctl >/dev/null 2>&1 && \
    systemextensionsctl list 2>/dev/null | grep -iq "carbonblack" && return 0
  return 1
}

has_ms_defender() {
  # Microsoft Defender for Endpoint
  if command -v mdatp >/dev/null 2>&1; then
    # Prefer a health probe if available
    ( mdatp health --field real_time_protection_enabled 2>/dev/null | grep -qi "true" ) && return 0
    ( mdatp health --field healthy 2>/dev/null | grep -qi "true" ) && return 0
  fi
  is_fproc "wdavdaemon" && return 0
  return 1
}

has_sophos() {
  # Sophos Intercept X / Endpoint
  is_proc "SophosScanD" && return 0
  is_fproc "com.sophos" && return 0
  return 1
}

has_symantec() {
  # Symantec Endpoint Protection
  is_proc "SymDaemon" && return 0
  return 1
}

has_trendmicro() {
  # Trend Micro Apex One (macOS)
  is_proc "iCoreService" && return 0
  command -v systemextensionsctl >/dev/null 2>&1 && \
    systemextensionsctl list 2>/dev/null | grep -Fq "com.trendmicro.icore.es" && return 0
  return 1
}

has_cortex_xdr() {
  # Palo Alto Networks Cortex XDR (aka Traps)
  [[ -x "/Library/Application Support/PaloAltoNetworks/Traps/bin/cytool" ]] && return 0
  is_fproc "/Library/Application Support/PaloAltoNetworks/Traps/bin/pmd" && return 0
  [[ -e "/Library/LaunchDaemons/com.paloaltonetworks.cortex.pmd.plist" ]] && return 0
  return 1
}

has_jamf_protect() {
  is_proc "JamfProtectAgent" && return 0
  # protectctl exists but may not be on PATH everywhere
  if [[ -x "/usr/local/bin/protectctl" ]]; then /usr/local/bin/protectctl version >/dev/null 2>&1 && return 0; fi
  if command -v protectctl >/dev/null 2>&1; then protectctl version >/dev/null 2>&1 && return 0; fi
  return 1
}

has_cylance() {
  # Cylance / BlackBerry Protect
  [[ -e "/Library/LaunchDaemons/com.cylance.agent_service.plist" ]] && return 0
  is_fproc "CylanceSvc" && return 0
  return 1
}

has_eset() {
  # ESET Endpoint Security for macOS
  is_proc "esets_daemon" && return 0
  return 1
}

has_bitdefender() { is_proc "BDLDaemon" && return 0; return 1; }   # Bitdefender
has_malwarebytes() { is_proc "RTProtectionDaemon" && return 0; return 1; } # Malwarebytes
has_sentinelone() { command -v sentinelctl >/dev/null 2>&1 && sentinelctl version 2>/dev/null | grep -q "SentinelOne" && return 0; return 1; }

has_xprotect() {
  # Apple XProtect Remediator (built-in)
  if command -v xprotect >/dev/null 2>&1; then
    xprotect status 2>/dev/null | grep -Fq "launch scans: enabled" || return 1
    xprotect status 2>/dev/null | grep -Fq "background scans: enabled" || return 1
    return 0
  fi

  # Fallback for older macOS versions where only the XProtect process exists
  is_fproc "xprotect" && return 0
  is_proc "XProtect" && return 0
  return 1
}

has_any_edr() {
  has_bitdefender      && return 0
  has_malwarebytes     && return 0
  has_sentinelone      && return 0
  has_crowdstrike      && return 0
  has_carbonblack      && return 0
  has_ms_defender      && return 0
  has_sophos           && return 0
  has_symantec         && return 0
  has_trendmicro       && return 0
  has_cortex_xdr       && return 0
  has_jamf_protect     && return 0
  has_cylance          && return 0
  has_eset             && return 0
  has_xprotect         && return 0  # treat “good XProtect status” as EPP present
  return 1
}

if ! has_any_edr; then
  echo "epp_disabled"
fi
