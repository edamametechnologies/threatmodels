#!/bin/bash

launchctl load -w /System/Library/LaunchDaemons/com.apple.smbd.plist &&
defaults write /Library/Preferences/SystemConfiguration/com.apple.smb.server.plist EnabledServices -array disk
