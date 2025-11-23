#!/bin/bash

set -euo pipefail

if [[ -z "${HOME:-}" ]]; then
  HOME="$(eval echo "~$(id -un)")"
fi

found_pm=0

# --- Native CLIs / desktop apps (best-effort) ---
# Command names cover common Linux PMs (binary/CLI)
for bin in \
  1password op \
  keepassxc keepassxc-cli \
  bitwarden bw \
  enpass \
  pass gopass \
  lpass \
  proton-pass protonpass \
  keeper; do
  if command -v "$bin" >/dev/null 2>&1; then
    found_pm=1; break
  fi
done

# --- Chromium-family browser extensions (Chrome/Chromium/Edge/Brave/Vivaldi) ---
# Known Chrome Web Store IDs:
#  1Password  aeblfdkhhhdcdjpifhhbdiojplfjncoa
#  Bitwarden  nngceckbapebfimnlniiiahkandclblb
#  LastPass   hdokiejnpimakedhajhdlcegeplioahd
#  Dashlane   fdjamakpfbbddfjaooikfcpapjohcfmg
#  Keeper     bfogiafebfohielmmehodmfbbebbbpei
#  KeePassXC  oboonakemofpalcgghocfoadofidjkkk
#  Enpass     kmcfomidfpdkfieipokbalgegidffkal

if [[ $found_pm -eq 0 ]]; then
  ext_ids=(
    aeblfdkhhhdcdjpifhhbdiojplfjncoa
    nngceckbapebfimnlniiiahkandclblb
    hdokiejnpimakedhajhdlcegeplioahd
    fdjamakpfbbddfjaooikfcpapjohcfmg
    bfogiafebfohielmmehodmfbbebbbpei
    oboonakemofpalcgghocfoadofidjkkk
    kmcfomidfpdkfieipokbalgegidffkal
  )

  chromium_bases=(
    "$HOME/.config/google-chrome"
    "$HOME/.config/chromium"
    "$HOME/.config/microsoft-edge"
    "$HOME/.config/BraveSoftware/Brave-Browser"
    "$HOME/.config/vivaldi"
    # Flatpak variants:
    "$HOME/.var/app/com.google.Chrome/config/google-chrome"
    "$HOME/.var/app/org.chromium.Chromium/config/chromium"
    "$HOME/.var/app/com.microsoft.Edge/config/microsoft-edge"
    "$HOME/.var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser"
    "$HOME/.var/app/com.vivaldi.Vivaldi/config/vivaldi"
  )

  for base in "${chromium_bases[@]}"; do
    [[ -d "$base" ]] || continue
    # scan all profiles under the browser data root
    while IFS= read -r -d '' profile; do
      [[ -d "$profile/Extensions" ]] || continue
      for id in "${ext_ids[@]}"; do
        if [[ -d "$profile/Extensions/$id" ]]; then
          found_pm=1; break 3
        fi
      done
    done < <(find "$base" -maxdepth 1 -mindepth 1 -type d -print0 2>/dev/null)
  done
fi

# --- Firefox extensions (search extensions.json for well-known names) ---
if [[ $found_pm -eq 0 ]]; then
  ff_root="$HOME/.mozilla/firefox"
  if [[ -d "$ff_root" ]]; then
    while IFS= read -r -d '' ej; do
      if grep -Eiq '"name".*"(1Password|Bitwarden|LastPass|Dashlane|Keeper|KeePassXC|Enpass)"' "$ej"; then
        found_pm=1; break
      fi
    done < <(find "$ff_root" -type f -name 'extensions.json' -print0 2>/dev/null)
  fi
fi

# --- Result ---
if [[ $found_pm -eq 0 ]]; then
  echo "No password manager installed"
fi
