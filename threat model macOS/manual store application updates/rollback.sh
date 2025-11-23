#!/bin/bash

defaults write /Library/Preferences/com.apple.commerce.plist AutoUpdate -bool false;
defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallAppUpdates -bool false;
defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -bool false
