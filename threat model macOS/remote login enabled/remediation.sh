#!/bin/bash

# Disable Remote Login (SSH). Newer macOS releases no longer reliably honor
# systemsetup -setremotelogin off, so also unload the SSH LaunchDaemon. Try
# both approaches and ignore individual failures so at least one takes effect.
launchctl unload -w /System/Library/LaunchDaemons/ssh.plist 2>/dev/null
echo yes | systemsetup -setremotelogin off 2>/dev/null
