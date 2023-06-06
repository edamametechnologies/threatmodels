
macOS Threat Model (EN)
=======================

Contents
========

* [Edamame helper inactive](#edamame-helper-inactive)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [MDM profiles installed](#mdm-profiles-installed)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [JAMF remote administration enabled](#jamf-remote-administration-enabled)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [Wake On LAN enabled](#wake-on-lan-enabled)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [Manual Appstore updates](#manual-appstore-updates)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [Local firewall disabled](#local-firewall-disabled)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [Automatic login enabled](#automatic-login-enabled)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [Remote login enabled](#remote-login-enabled)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [Remote desktop enabled](#remote-desktop-enabled)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [File sharing enabled](#file-sharing-enabled)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [Remote events enabled](#remote-events-enabled)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [Corporate disk recovery key](#corporate-disk-recovery-key)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [Disk encryption disabled](#disk-encryption-disabled)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [Unsigned applications allowed](#unsigned-applications-allowed)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [Manual system updates](#manual-system-updates)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [Response to ping enabled](#response-to-ping-enabled)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [Screen lock disabled](#screen-lock-disabled)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [No antivirus installed](#no-antivirus-installed)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [System Integrity Protection disabled](#system-integrity-protection-disabled)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [Guest account enabled](#guest-account-enabled)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [Root user enabled](#root-user-enabled)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [Unprotected system changes](#unprotected-system-changes)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [Compromised Apple ID](#compromised-apple-id)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [Your OS is not up to date](#your-os-is-not-up-to-date)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)

# Edamame helper inactive

## Threat


**Dimension : system services / Severity : 5**

Edamame's Helper software is not running or requires an update. It's required for maximum Security Score analysis.
## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Command line|admin|ps -ef \| grep edamame_helper \| grep -v grep > /dev/null \|\| echo nohelper|

## Rollback
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Command line|user|https://edamamecompany.sharepoint.com/:u:/s/Anyone/EW70U3YGjwdFryyIzVo3maMBNE6XAb0ZabQ0Bi0uAw5vsQ?e=7kVnf4|

## Remediation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Command line|system|/Library/Application\ Support/Edamame/Edamame-Helper/uninstall.sh|

# MDM profiles installed

## Threat


**Dimension : system integrity / Severity : 5**

You have one or more Mobile Device Management (MDM) profiles installed on your computer. This means that your computer is or can be remotely administered by a 3rd party. If this is your personal computer, this is a grave threat and the profiles should be removed.
## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Command line|system|profiles list \| grep profileIdentifier|

## Rollback
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Command line|system|profiles remove -all|

## Remediation


https://en.wikipedia.org/wiki/Mobile_device_management
# JAMF remote administration enabled

## Threat


**Dimension : system integrity / Severity : 5**

Your computer is or can be remotely administered by a 3rd party using the JAMF MDM framework. If this is your personal computer, this is a grave threat and JAMF should be removed.
## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Command line|admin|pgrep jamf|

## Rollback
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Command line|system|jamf removeFramework|

## Remediation


https://www.jamf.com/en
# Wake On LAN enabled

## Threat


**Dimension : network / Severity : 1**

*Tags : CIS Benchmark Level 1, macos_security/sysprefs_wake_network_access_disable*

Wake on LAN is a feature that can wake up your computer automatically when something is attempting to connect to it. This is not something you need in most cases and it can allow an attacker to connect to your computer at any time.
## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Command line|system|systemsetup getwakeonnetworkaccess \| grep -v Off|

## Rollback
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Command line|system|systemsetup -setwakeonnetworkaccess off|

## Remediation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Command line|system|systemsetup -setwakeonnetworkaccess on|

# Manual Appstore updates

## Threat


**Dimension : applications / Severity : 3**

*Tags : CIS Benchmark Level 1, macos_security/sysprefs_software_update_app_update_enforce*

Applications are constantly updated to fix potential security issues. It's your best interest to get updates as soon as you can through automatic updates.
## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Command line|admin|defaults read /Library/Preferences/com.apple.commerce.plist AutoUpdate 2>&1 \| grep -v 1|

## Rollback
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Command line|system|defaults write /Library/Preferences/com.apple.commerce.plist AutoUpdate -bool true; defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallAppUpdates -bool true|

## Remediation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Command line|system|defaults write /Library/Preferences/com.apple.commerce.plist AutoUpdate -bool false; defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallAppUpdates -bool false|

# Local firewall disabled

## Threat


**Dimension : network / Severity : 2**

*Tags : CIS Benchmark Level 1, macos_security/sysprefs_firewall_enable*

Your local firewall is disabled. This is fine in a trusted environment but dangerous if you happened to connect to public networks. You should turn it on by default.
## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Command line|admin|defaults read /Library/Preferences/com.apple.alf globalstate \| grep 0|

## Rollback
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Command line|system|defaults write /Library/Preferences/com.apple.alf globalstate -int 2|

## Remediation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Command line|system|defaults write /Library/Preferences/com.apple.alf globalstate -int 0|

# Automatic login enabled

## Threat


**Dimension : credentials / Severity : 4**

*Tags : CIS Benchmark Level 1, macos_security/sysprefs_automatic_login_disable*

Automatic login could appear as very handy but in fact it's a major security threat: it allows anyone to access your data without knowing your password.
## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Command line|user|defaults read /Library/Preferences/com.apple.loginwindow \| grep autoLoginUser|

## Rollback
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Command line|system|defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser|

## Remediation


https://www.youtube.com/watch?v=G89On8uvQuQ
# Remote login enabled

## Threat


**Dimension : system integrity / Severity : 4**

*Tags : CIS Benchmark Level 1, macos_security/sysprefs_ssh_disable*

Remote login is enabled. This is not necessary unless your are an IT professional. This is unusual and dangerous for most users.
## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Command line|system|systemsetup -getremotelogin \| grep On|

## Rollback
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Command line|fulldisk|echo yes \| systemsetup -setremotelogin off|

## Remediation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Command line|fulldisk|systemsetup -setremotelogin on|

# Remote desktop enabled

## Threat


**Dimension : system integrity / Severity : 4**

*Tags : CIS Benchmark Level 1, macos_security/sysprefs_remote_management_disable*

Remote desktop is enabled. This is not necessary unless your are an IT professional. This is unusual and dangerous for most users.
## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Command line|admin|pgrep ARDAgent|

## Rollback
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Command line|system|/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -deactivate -configure -access -off|

## Remediation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Command line|system|/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -restart -agent|

# File sharing enabled

## Threat


**Dimension : system services / Severity : 4**

*Tags : CIS Benchmark Level 1, macos_security/sysprefs_smbd_disable*

File sharing is enabled. While this could be intentional we strongly recommend to turn it off. It's not that easy to configure and can expose your data to unwanted people.
## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Command line|admin|pgrep smbd|

## Rollback
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Command line|system|launchctl unload -w /System/Library/LaunchDaemons/com.apple.smbd.plist|

## Remediation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Command line|system|launchctl load -w /System/Library/LaunchDaemons/com.apple.smbd.plist; defaults write /Library/Preferences/SystemConfiguration/com.apple.smb.server.plist EnabledServices -array disk|

# Remote events enabled

## Threat


**Dimension : system integrity / Severity : 4**

*Tags : CIS Benchmark Level 1, macos_security/sysprefs_rae_disable*

Remote events are enabled. While this could be intentional we strongly recommend to turn it off. It's unnecessary for most users and has been a target for exploit in the recent past.
## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Command line|system|launchctl print-disabled system \| grep com.apple.AEServer \| grep false|

## Rollback
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Command line|fulldisk|systemsetup -setremoteappleevents off|

## Remediation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Command line|fulldisk|systemsetup -setremoteappleevents on|

# Corporate disk recovery key

## Threat


**Dimension : system integrity / Severity : 4**

It seems your computer hard disk has been encrypted by your employer. It means that they could potentially decrypt it if you give the computer back to them. You should suppress that possibility.
## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Command line|system|fdesetup hasinstitutionalrecoverykey \| grep true|

## Rollback


https://derflounder.wordpress.com/2019/07/03/managing-macos-mojaves-filevault-2-with-fdesetup/
## Remediation


https://derflounder.wordpress.com/2019/07/03/managing-macos-mojaves-filevault-2-with-fdesetup/
# Disk encryption disabled

## Threat


**Dimension : system services / Severity : 4**

*Tags : CIS Benchmark Level 1, macos_security/sysprefs_filevault_enforce*

Your main storage is not encrypted. While there is a little performance impact by enabling it, we really urge you to set it up. Without that anyone physically accessing your computer can access your data.
## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Command line|admin|fdesetup isactive \| grep false|

## Rollback


https://www.youtube.com/watch?v=ETgLlx3Npqg
## Remediation


https://www.youtube.com/watch?v=ETgLlx3Npqg
# Unsigned applications allowed

## Threat


**Dimension : applications / Severity : 4**

*Tags : CIS Benchmark Level 1, macos_security/os_gatekeeper_enable*

Your computer has been setup to allow unsigned applications to run. This is unusual and dangerous. You should turn this off.
## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Command line|admin|spctl --status \| grep disabled|

## Rollback
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Command line|system|spctl --global-enable|

## Remediation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Command line|system|spctl --global-disable|

# Manual system updates

## Threat


**Dimension : system integrity / Severity : 4**

*Tags : CIS Benchmark Level 1, macos_security/sysprefs_install_macos_updates_enforce, macos_security/sysprefs_software_update_download_enforce*

System updates are manual. Your really should turn on automatic system updates to get the latest security fixes for your computer.
## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Command line|admin|defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates 2>&1 \| grep -v 1|

## Rollback
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Command line|system|defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true; defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool true; defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -bool true; defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true; defaults write /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall -bool true; softwareupdate --schedule on|

## Remediation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Command line|system|defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool false; defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool false; defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -bool false; defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool false; defaults write /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall -bool false; softwareupdate --schedule off|

# Response to ping enabled

## Threat


**Dimension : network / Severity : 3**

*Tags : CIS Benchmark Level 1, macos_security/sysprefs_firewall_stealth_mode_enable*

Your computer will respond if anything on the network is trying to check its presence. This can be very bad and allow anyone to check your presence and possibly attack your computer.
## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Command line|admin|/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode \| grep disabled|

## Rollback
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Command line|system|/usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on|

## Remediation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Command line|system|/usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode off|

# Screen lock disabled

## Threat


**Dimension : credentials / Severity : 3**

*Tags : CIS Benchmark Level 1, macos_security/sysprefs_screensaver_ask_for_password_delay_enforce*

Your computer doesn't have a screensaver enabled with a password. It leaves it open for phsyical access by anyone. This is very dangerous!
## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Command line|user|sysadminctl -screenLock status 2>&1 \| grep off|

## Rollback


https://www.youtube.com/watch?v=C6of13nZTpM
## Remediation


https://www.youtube.com/watch?v=C6of13nZTpM
# No antivirus installed

## Threat


**Dimension : applications / Severity : 4**

You don't have any antivirus installed. We recommend you to install one.
## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Command line|admin|pgrep RTProtectionDaemon >/dev/null \|\| echo noepp|

## Rollback


https://www.malwarebytes.com/
## Remediation


https://support.malwarebytes.com/hc/en-us/articles/360039023473-Uninstall-and-reinstall-Malwarebytes-using-the-Malwarebytes-Support-Tool
# System Integrity Protection disabled

## Threat


**Dimension : system integrity / Severity : 5**

*Tags : CIS Benchmark Level 1, macos_security/os_sip_enable*

System Integrity Protection is a great ability of macOS that prevents any software to change system files and components. To some extent it's a "good enough" antivirus for your Mac. Having it disabled is... unusual and dangerous. It should be enabled by default on your Mac. This content will explain a way to enable it again. Bear with me .. it's somewhat hard to achieve!
## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Command line|user|csrutil status \| grep disabled|

## Rollback


https://www.youtube.com/watch?v=Fx_1OPFzu88
## Remediation


https://www.youtube.com/watch?v=StAn0ZHiXTc
# Guest account enabled

## Threat


**Dimension : system services / Severity : 2**

*Tags : CIS Benchmark Level 1, macos_security/sysprefs_guest_account_disable*

Guest account is enabled. This is usually fine but it's not that easy to limit access to your data. You should disable it.
## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Command line|user|sysadminctl -guestAccount status 2>&1 \| grep enabled|

## Rollback
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Command line|system|sysadminctl -guestAccount off|

## Remediation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Command line|system|sysadminctl -guestAccount on|

# Root user enabled

## Threat


**Dimension : system integrity / Severity : 3**

A special system user has been configured on your computer. This is unusual and should be disabled immediately.
## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Command line|user|dscl . -read /Users/root Password \| grep "\*\*"|

## Rollback


https://www.youtube.com/watch?v=Sx8o8C1oqyc
## Remediation


https://www.youtube.com/watch?v=Sx8o8C1oqyc
# Unprotected system changes

## Threat


**Dimension : system integrity / Severity : 3**

*Tags : CIS Benchmark Level 1, macos_security/sysprefs_system_wide_preferences_configure*

Your computer system settings can be modified by any users. You should restrict it.
## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Command line|user|security authorizationdb read system.preferences 2> /dev/null \| grep -A1 shared \| grep true|

## Rollback
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Command line|system|security authorizationdb read system.preferences > /tmp/system.preferences.plist; /usr/libexec/PlistBuddy -c "Set :shared false" /tmp/system.preferences.plist; security authorizationdb write system.preferences < /tmp/system.preferences.plist|

## Remediation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Command line|system|security authorizationdb read system.preferences > /tmp/system.preferences.plist; /usr/libexec/PlistBuddy -c "Set :shared true" /tmp/system.preferences.plist; security authorizationdb write system.preferences < /tmp/system.preferences.plist|

# Compromised Apple ID

## Threat


**Dimension : credentials / Severity : 1**

Your Apple ID email has recently appeared in a data breach, please review the breach and change your passwords accordingly.
## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Command line|user|pwned -i 365|

## Rollback
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Command line||digitalidentity_manager|

## Remediation


https://haveibeenpwned.com/
# Your OS is not up to date

## Threat


**Dimension : system integrity / Severity : 2**

Your operating system is not up to date, please proceed to upgrade to get the latest security patches.
## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Command line|admin|defaults read /Library/Preferences/com.apple.SoftwareUpdate.plist \| grep macOS|

## Rollback


https://www.youtube.com/watch?v=FG2DXkPA93g&t=124s
## Remediation


https://www.youtube.com/watch?v=FG2DXkPA93g&t=124s