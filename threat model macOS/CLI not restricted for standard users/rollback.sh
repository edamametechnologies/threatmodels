#!/bin/bash

python3 - <<'PY'
skip = False
lines = []
with open("/etc/zshrc") as src:
    for line in src:
        if "BEGIN RESTRICT_ZSH_NONADMINS" in line:
            skip = True
            continue
        if "END RESTRICT_ZSH_NONADMINS" in line:
            skip = False
            continue
        if not skip:
            lines.append(line)
with open("/etc/zshrc", "w") as dst:
    dst.writelines(lines)
print("[OK] zsh block removed")
PY
