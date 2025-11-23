#!/bin/bash

defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true;
defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool true;
defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -bool true;
defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true;
defaults write /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall -bool true;
softwareupdate --schedule on
