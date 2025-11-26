#!/bin/sh

ensure_home() {
  if [ -n "${HOME:-}" ] && [ -d "${HOME}" ]; then
    return
  fi

  local user
  user="$(id -un)"

  if command -v getent >/dev/null 2>&1; then
    HOME="$(getent passwd "${user}" | cut -d: -f6)"
    if [ -n "${HOME}" ] && [ -d "${HOME}" ]; then
      return
    fi
  fi

  HOME="$(eval echo "~${user}")"
  if [ -n "${HOME}" ] && [ -d "${HOME}" ]; then
    return
  fi

  HOME="/root"
}

ensure_home

found_pm=0

# --- Native CLIs ---
pm_bins="1password op keepassxc keepassxc-cli bitwarden bw enpass pass gopass lpass proton-pass protonpass keeper"

for bin in $pm_bins; do
  if command -v "$bin" >/dev/null 2>&1; then
    found_pm=1
    break
  fi
done

if [ "$found_pm" -eq 1 ]; then
    exit 0
fi

# --- Chrome Extensions ---
ext_ids="aeblfdkhhhdcdjpifhhbdiojplfjncoa nngceckbapebfimnlniiiahkandclblb hdokiejnpimakedhajhdlcegeplioahd fdjamakpfbbddfjaooikfcpapjohcfmg bfogiafebfohielmmehodmfbbebbbpei oboonakemofpalcgghocfoadofidjkkk kmcfomidfpdkfieipokbalgegidffkal"

chromium_bases="$HOME/.config/google-chrome $HOME/.config/chromium $HOME/.config/microsoft-edge $HOME/.config/BraveSoftware/Brave-Browser $HOME/.config/vivaldi $HOME/.var/app/com.google.Chrome/config/google-chrome $HOME/.var/app/org.chromium.Chromium/config/chromium $HOME/.var/app/com.microsoft.Edge/config/microsoft-edge $HOME/.var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser $HOME/.var/app/com.vivaldi.Vivaldi/config/vivaldi"

for base in $chromium_bases; do
  if [ -d "$base" ]; then
      # Iterate over profiles (subdirectories)
      for profile in "$base"/*; do
        if [ -d "$profile" ] && [ -d "$profile/Extensions" ]; then
            for id in $ext_ids; do
                if [ -d "$profile/Extensions/$id" ]; then
                    found_pm=1
                    exit 0
                fi
            done
        fi
      done
  fi
  done

# --- Firefox ---
  ff_root="$HOME/.mozilla/firefox"
if [ -d "$ff_root" ]; then
    # Search for extensions.json containing known names
    if find "$ff_root" -type f -name 'extensions.json' -exec grep -Eiq '"name".*"(1Password|Bitwarden|LastPass|Dashlane|Keeper|KeePassXC|Enpass)"' {} +; then
        found_pm=1
        exit 0
  fi
fi

if [ "$found_pm" -eq 0 ]; then
  echo "No password manager installed"
fi
