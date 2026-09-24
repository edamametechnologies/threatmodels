#!/bin/bash

set -euo pipefail

ensure_home() {
  if [[ -n "${HOME:-}" && -d "${HOME}" ]]; then
    return
  fi

  local user
  user="$(id -un)"

  # macOS: prefer dscl lookup
  if HOME="$(/usr/bin/dscl . -read "/Users/${user}" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"; then
    if [[ -n "${HOME}" && -d "${HOME}" ]]; then
      return
    fi
  fi

  # Fallback to tilde expansion
  if HOME="$(eval echo "~${user}")" && [[ -n "${HOME}" && -d "${HOME}" ]]; then
    return
  fi

  # Absolute last resort
  HOME="/var/root"
}

ensure_home

found_pm=0

# Browser extension display names that count as a password manager (matched as a prefix)
pm_names='1Password|Bitwarden|LastPass|Dashlane|Keeper|Enpass|NordPass|RoboForm|Zoho Vault|Proton Pass|KeePassXC'
pm_name_re="(${pm_names})([^[:alpha:]\"][^\"]*)?"

# --- Native (desktop or App Store “container” apps incl. Safari extensions) ---
app_names=(
  "1Password.app"
  "1Password 7.app"      # legacy
  "1Password7.app"       # legacy naming
  "1Password for Safari.app"
  "Bitwarden.app"
  "LastPass.app"
  "LastPass for Safari.app"
  "Dashlane.app"
  "Keeper Password Manager.app"
  "Keeper for Safari.app"
  "Enpass.app"
  "KeePassXC.app"
  "NordPass.app"
  "RoboForm.app"
  "Zoho Vault.app"
  "Proton Pass.app"
  "Chrome Apps.localized/Google Password Manager.app"
)

for app_dir in "/Applications" "$HOME/Applications"; do
  for app in "${app_names[@]}"; do
    if [[ -d "$app_dir/$app" ]]; then
      found_pm=1; break 2
    fi
  done
done

# --- Chromium-family extensions (Chrome, Chromium, Edge, Brave, Vivaldi, Arc, Opera) ---
# Known extension IDs
chrome_ids=(
  # Chrome Web Store
  "aeblfdkhhhdcdjpifhhbdiojplfjncoa"   # 1Password – Password Manager (stable)
  "khgocmkkpikpnmmkgmdnfckapcdkgfaf"   # 1Password Beta
  "nngceckbapebfimnlniiiahkandclblb"   # Bitwarden
  "hdokiejnpimakedhajhdlcegeplioahd"   # LastPass
  "fdjamakpfbbddfjaooikfcpapjohcfmg"   # Dashlane
  "bfogiafebfohielmmehodmfbbebbbpei"   # Keeper
  "igkpcodhieompeloncfnbekccinhapdb"   # Zoho Vault
  "eiaeiblijfjekdanodkjadfinkhbfgcd"   # NordPass
  "pnlccmojcmeohlpggmfnbbiapkmbliob"   # RoboForm
  "oboonakemofpalcgghocfoadofidjkkk"   # KeePassXC-Browser
  "kmcfomidfpdkfieipokbalgegidffkal"   # Enpass
  "ghmbeldphafepmbegfdlkpapadhbakde"   # Proton Pass
  # Microsoft Edge Add-ons (where they differ from Chrome)
  "dppgmdbiimibapkepcbdbmkaabgiofem"   # 1Password
  "jbkfoedolllekgbhcbcoahefnbanhhlh"   # Bitwarden
  "pdffhmdngciaglkoonimfcmckehcpafo"   # KeePassXC-Browser
)

chromium_bases=(
  "$HOME/Library/Application Support/Google/Chrome"
  "$HOME/Library/Application Support/Chromium"
  "$HOME/Library/Application Support/Microsoft Edge"
  "$HOME/Library/Application Support/BraveSoftware/Brave-Browser"
  "$HOME/Library/Application Support/Vivaldi"
  "$HOME/Library/Application Support/Arc/User Data"
  "$HOME/Library/Application Support/com.operasoftware.Opera"   # default profile lives at the root
)

# Display names of an installed extension version: manifest "name"/"short_name",
# with "__MSG_key__" placeholders resolved from the extension's locale files
chromium_ext_names() {
  local ext_dir="$1" manifest locale value key messages
  manifest="$(tr -d '\r\n' < "$ext_dir/manifest.json")" || return 0
  locale="$(printf '%s' "$manifest" | sed -n -E 's/.*"default_locale"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/p')"

  while IFS= read -r value; do
    if [[ "$value" =~ ^__MSG_(.+)__$ ]]; then
      key="${BASH_REMATCH[1]}"
      for messages in "$ext_dir/_locales/${locale:-en}/messages.json" "$ext_dir/_locales/en/messages.json"; do
        [[ -f "$messages" ]] || continue
        tr -d '\r\n' < "$messages" \
          | grep -o -i -E "\"${key}\"[[:space:]]*:[[:space:]]*\{[^}]*\"message\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" \
          | sed -E 's/.*"([^"]*)"$/\1/' || true
        break
      done
    else
      printf '%s\n' "$value"
    fi
  done < <(printf '%s' "$manifest" \
    | grep -o -E '"(name|short_name)"[[:space:]]*:[[:space:]]*"[^"]*"' \
    | sed -E 's/.*"([^"]*)"$/\1/' || true)
}

chromium_profile_has_pm() {
  local ext_root="$1/Extensions" id ext_dir names
  [[ -d "$ext_root" ]] || return 1

  for id in "${chrome_ids[@]}"; do
    if [[ -d "$ext_root/$id" ]]; then
      return 0
    fi
  done

  # Name fallback: other stores, self-hosted or policy-deployed builds with unknown IDs
  for ext_dir in "$ext_root"/*/*/; do
    [[ -f "$ext_dir/manifest.json" ]] || continue
    names="$(chromium_ext_names "${ext_dir%/}")"
    if grep -Eiq "^${pm_name_re}\$" <<< "$names"; then
      return 0
    fi
  done
  return 1
}

if [[ $found_pm -eq 0 ]]; then
  for base in "${chromium_bases[@]}"; do
    [[ -d "$base" ]] || continue
    for profile in "$base" "$base"/*; do
      if [[ -d "$profile" ]] && chromium_profile_has_pm "$profile"; then
        found_pm=1; break 2
      fi
    done
  done
fi

# --- Firefox extensions (look for known names in extensions.json) ---
if [[ $found_pm -eq 0 ]]; then
  ff_root="$HOME/Library/Application Support/Firefox/Profiles"
  if [[ -d "$ff_root" ]]; then
    for prof in "$ff_root"/*; do
      ej="$prof/extensions.json"
      if [[ -f "$ej" ]] && \
         grep -Eiq "\"name\"[[:space:]]*:[[:space:]]*\"${pm_name_re}\"" "$ej"; then
        found_pm=1; break
      fi
    done
  fi
fi

# --- Result ---
if [[ $found_pm -eq 0 ]]; then
  echo "No password manager installed"
fi
