#!/bin/bash

set -euo pipefail

found_pm=0

# --- Native (desktop or App Store “container” apps incl. Safari extensions) ---
app_paths=(
  "/Applications/1Password.app"
  "/Applications/1Password 7.app"      # legacy
  "/Applications/1Password7.app"       # legacy naming
  "/Applications/1Password for Safari.app"
  "/Applications/Bitwarden.app"
  "/Applications/LastPass.app"
  "/Applications/LastPass for Safari.app"
  "/Applications/Dashlane.app"
  "/Applications/Keeper Password Manager.app"
  "/Applications/Keeper for Safari.app"
  "/Applications/Enpass.app"
  "/Applications/KeePassXC.app"
  "/Applications/NordPass.app"
  "/Applications/RoboForm.app"
  "/Applications/Zoho Vault.app"
  "/Applications/Proton Pass.app"
  "$HOME/Applications/Chrome Apps.localized/Google Password Manager.app"
)

for p in "${app_paths[@]}"; do
  if [[ -d "$p" ]]; then
    found_pm=1; break
  fi
done

# --- Chromium-family extensions (Chrome, Edge, Brave, Vivaldi) ---
# Known extension IDs
chrome_ids=(
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
)

chromium_bases=(
  "$HOME/Library/Application Support/Google/Chrome"
  "$HOME/Library/Application Support/Microsoft Edge"
  "$HOME/Library/Application Support/BraveSoftware/Brave-Browser"
  "$HOME/Library/Application Support/Vivaldi"
)

if [[ $found_pm -eq 0 ]]; then
  for base in "${chromium_bases[@]}"; do
    [[ -d "$base" ]] || continue
    for profile in "$base"/*; do
      [[ -d "$profile/Extensions" ]] || continue
      for id in "${chrome_ids[@]}"; do
        if [[ -d "$profile/Extensions/$id" ]]; then
          found_pm=1; break
        fi
      done
      [[ $found_pm -eq 1 ]] && break
    done
    [[ $found_pm -eq 1 ]] && break
  done
fi

# --- Firefox extensions (look for known names in extensions.json) ---
if [[ $found_pm -eq 0 ]]; then
  ff_root="$HOME/Library/Application Support/Firefox/Profiles"
  if [[ -d "$ff_root" ]]; then
    for prof in "$ff_root"/*; do
      ej="$prof/extensions.json"
      if [[ -f "$ej" ]] && \
         grep -Eiq '"name".*"(1Password|Bitwarden|LastPass|Dashlane|Keeper|Enpass|NordPass|Zoho Vault|Proton Pass|KeePassXC)"' "$ej"; then
        found_pm=1; break
      fi
    done
  fi
fi

# --- Result ---
if [[ $found_pm -eq 0 ]]; then
  echo "No password manager installed"
fi
