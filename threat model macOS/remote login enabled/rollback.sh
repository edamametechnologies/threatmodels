#!/bin/bash

# Enable Remote Login (SSH). Newer macOS releases no longer reliably honor
# systemsetup -setremotelogin on, so also load the SSH LaunchDaemon. Try both
# approaches and ignore individual failures so at least one takes effect.
launchctl load -w /System/Library/LaunchDaemons/ssh.plist 2>/dev/null
systemsetup -setremotelogin on 2>/dev/null
