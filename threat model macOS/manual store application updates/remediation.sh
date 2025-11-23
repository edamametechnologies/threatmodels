#!/bin/bash

defaults write /Library/Preferences/com.apple.commerce.plist AutoUpdate -bool true;
defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallAppUpdates -bool true;
defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -bool true
