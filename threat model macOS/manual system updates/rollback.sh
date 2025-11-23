#!/bin/bash

defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool false;
defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool false;
defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -bool false;
defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool false;
defaults write /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall -bool false;
softwareupdate --schedule off
