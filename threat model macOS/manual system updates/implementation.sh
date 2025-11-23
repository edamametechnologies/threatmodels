#!/bin/bash

defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates 2>/dev/null | grep -q 1 ||
echo macosupdate_disabled
