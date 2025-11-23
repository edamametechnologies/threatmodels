#!/bin/bash

grep -q "BEGIN RESTRICT_ZSH_NONADMINS" /etc/zshrc ||
cat <<'EOF' >> /etc/zshrc
# BEGIN RESTRICT_ZSH_NONADMINS
## Prevent non-admin users from using interactive zsh shells
if [[ -t 1 ]];
then
  if ! id -Gn | grep -qw admin;
then
    echo ""
    echo "Command-line access is restricted by your administrator."
    osascript -e "display alert \"Access Restricted\" message \"Command-line tools are blocked for standard users.\" buttons {\"OK\"}" 2>/dev/null ||
true
    exit 1
  fi
fi
# END RESTRICT_ZSH_NONADMINS
EOF
