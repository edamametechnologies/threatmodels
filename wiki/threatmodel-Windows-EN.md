
Windows Threat Model (EN)
=========================

Contents
========

* [Edamame helper inactive](#edamame-helper-inactive)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [Cached logon credentials enabled](#cached-logon-credentials-enabled)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [Windows Defender Disabled](#windows-defender-disabled)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [Automatic updates of App store apps disabled](#automatic-updates-of-app-store-apps-disabled)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [User Account Control disabled](#user-account-control-disabled)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [SMBv1 Protocol Enabled](#smbv1-protocol-enabled)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [Automatic logon enabled](#automatic-logon-enabled)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [Windows Script Host enabled](#windows-script-host-enabled)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [Remote Desktop Protocol (RDP) enabled](#remote-desktop-protocol-rdp-enabled)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [Windows Update disabled](#windows-update-disabled)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [Guest account enabled](#guest-account-enabled)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [Autoplay enabled](#autoplay-enabled)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [Built-in Administrator account enabled](#built-in-administrator-account-enabled)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [Windows Firewall disabled](#windows-firewall-disabled)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [Remote Registry Service enabled](#remote-registry-service-enabled)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [LM and NTLMv1 protocols enabled](#lm-and-ntlmv1-protocols-enabled)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [Lsass.exe process protection not enabled](#lsassexe-process-protection-not-enabled)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [PowerShell execution policy not set to RemoteSigned](#powershell-execution-policy-not-set-to-remotesigned)
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
|Windows 12|Command line|user|$result = if ((Get-Service -Name edamame_helper -ErrorAction SilentlyContinue).Status -eq 'Running') { "" } else { "no helper" }; $result
|

## Rollback
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 12|Command line|user|https://edamamecompany.sharepoint.com/:u:/s/Anyone/EY31rA1xkKpIpnvVrz95Zv4BGesgmjBSl9xuzCZx6hDk8w?e=rlaNKz|

## Remediation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 12|Command line|user|h|

# Cached logon credentials enabled

## Threat


**Dimension : credentials / Severity : 4**

Cached logon credentials are a security risk as they can be used by attackers to gain access to your system. They are stored on your system and can be retrieved by attackers who gain access to your computer or network. We recommend disabling cached logon credentials to increase the security of your system.
## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Command line|user|if(((Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI' -Name 'DisablePasswordCaching' -ErrorAction SilentlyContinue).DisablePasswordCaching) -eq 1) { 'Password caching is disabled' } else { '' }|

## Rollback
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Command line|admin|reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI' /v DisablePasswordCaching /t REG_DWORD /d 1 /f|

## Remediation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Command line|admin|reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI' /v DisablePasswordCaching /t REG_DWORD /d 0 /f|

# Windows Defender Disabled

## Threat


**Dimension : applications / Severity : 5**

*Tags : CIS Benchmark Level 1, windows_security/wd_disabled*

Windows Defender is a built-in antivirus and antimalware software that comes with Windows. Disabling it can leave your system vulnerable to various threats, such as viruses, Trojans, and spyware.
## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Command line|user|if((Get-MpPreference \| Select-Object -ExpandProperty DisableRealtimeMonitoring) -eq $true) { 'Real-time monitoring is disabled' } else { '' }|

## Rollback
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Command line|admin|Set-MpPreference -DisableRealtimeMonitoring $false|

## Remediation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Command line|admin|Set-MpPreference -DisableRealtimeMonitoring $true|

# Automatic updates of App store apps disabled

## Threat


**Dimension : system services / Severity : 3**

*Tags : CIS Benchmark Level 1, windows_10_1709*

Automatic updates of App store apps is disabled which may result in outdated apps and pose a risk to security. It is recommended to enable automatic updates of App store apps.
## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|windows 10|Command line|user|if((Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore' -ErrorAction SilentlyContinue).AutoDownload -ne 4) { 'Automatic updates of App store apps disabled' } else { '' }|

## Rollback
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|windows 10|Command line|admin|reg add 'HKLM\SOFTWARE\Policies\Microsoft\WindowsStore' /v AutoDownload /t REG_DWORD /d 4 /f|

## Remediation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|windows 10|Command line|admin|reg add 'HKLM\SOFTWARE\Policies\Microsoft\WindowsStore' /v AutoDownload /t REG_DWORD /d 2 /f|

# User Account Control disabled

## Threat


**Dimension : system integrity / Severity : 5**

*Tags : CIS Benchmark Level 2, windows_security/uac_enable*

User Account Control (UAC) is a security feature in Windows that helps prevent unauthorized changes to your computer. If UAC is disabled, it's easier for malware to make changes to your system without your knowledge. You should enable UAC to protect your system from such attacks.
## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Command line|user|if((Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue).EnableLUA -eq 0) { 'UAC disabled' } else { '' }|

## Rollback
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Command line|admin|Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1 -Type DWord|

## Remediation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Command line|admin|Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 0 -Type DWord|

# SMBv1 Protocol Enabled

## Threat


**Dimension : network / Severity : 5**

*Tags : CIS Benchmark Level 1, windows_security/smb1_protocol_disabled*

The SMBv1 protocol is enabled on your system. This protocol is outdated and has known vulnerabilities that can allow attackers to take over your system. It should be disabled to improve your system's security.
## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Command line|user|if((Get-SmbServerConfiguration).EnableSMB1Protocol -eq $true) { 'SMBv1 enabled' } else { '' }|

## Rollback
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Command line|admin|Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol|

## Remediation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Command line|admin|Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol|

# Automatic logon enabled

## Threat


**Dimension : credentials / Severity : 4**

Automatic logon allows the system to automatically log on a user after booting up. This can be a security risk if the system is not physically secured as anyone can access the system without providing any credentials. It is recommended to disable automatic logon.
## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Command line|user|if((Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue).AutoAdminLogon -eq '1') { 'Automatic logon enabled' } else { '' }|

## Rollback
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Command line|admin|Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon -Value 0|

## Remediation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Command line|admin|Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon -Value 1|

# Windows Script Host enabled

## Threat


**Dimension : system integrity / Severity : 4**

*Tags : CIS Benchmark Level 1, windows_security/disable_wscript_host*

Windows Script Host is a built-in Windows scripting environment that allows running of VBScript, JScript, and other scripting languages. Disabling it can help mitigate some types of malware attacks.
## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Command line|user|if((Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' -Name Enabled -ErrorAction SilentlyContinue).Enabled -eq 1) { 'Windows Script Host enabled' } else { '' }|

## Rollback
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Command line|admin|reg add 'HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings' /v Enabled /t REG_DWORD /d 0 /f|

## Remediation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Command line|admin|reg add 'HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings' /v Enabled /t REG_DWORD /d 1 /f|

# Remote Desktop Protocol (RDP) enabled

## Threat


**Dimension : network / Severity : 4**

*Tags : CIS Benchmark Level 1, windows_security/rdp_enable*

RDP allows users to remotely access and control a Windows computer from another location. While this can be convenient, it also presents a significant security risk if left enabled and unprotected. An attacker could potentially gain access to your computer and compromise your sensitive data or even take control of your system.
## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Command line|user|if((Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction SilentlyContinue) -eq 0) { 'Terminal Services connections allowed' } else { '' }|

## Rollback
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Command line|admin|Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 1|

## Remediation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Command line|admin|Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0|

# Windows Update disabled

## Threat


**Dimension : system integrity / Severity : 5**

*Tags : CIS Benchmark Level 1, windows_security/update_automatic_updates*

Disabling Windows Update prevents critical security patches and updates from being installed on your system, leaving your system vulnerable to known exploits and threats. It is highly recommended that you enable Windows Update to ensure your system is up to date with the latest security patches.
## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Command line|user|if((Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name NoAutoUpdate -ErrorAction SilentlyContinue) -ne $null) { 'NoAutoUpdate is set' } else { '' }|

## Rollback
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Command line|admin|reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' /v NoAutoUpdate /t REG_DWORD /d 0 /f|

## Remediation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Command line|admin|reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' /v NoAutoUpdate /t REG_DWORD /d 1 /f|

# Guest account enabled

## Threat


**Dimension : credentials / Severity : 4**

*Tags : CIS Benchmark Level 1, windows_security/accounts_guest_account*

The Guest account is a default account in Windows, which allows users to access the system with limited privileges. It's recommended to disable this account to prevent unauthorized access to your system and data.
## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Command line|user|if((Get-WmiObject -Class Win32_UserAccount \| Where-Object {$_.Name -eq 'Guest'} \| Select-Object -Property Name).Name -eq 'Guest') { 'Guest account exists' } else { '' }|

## Rollback
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Command line|admin|Disable-LocalUser -Name Guest|

## Remediation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Command line|admin|Enable-LocalUser -Name Guest|

# Autoplay enabled

## Threat


**Dimension : system services / Severity : 3**

*Tags : CIS Benchmark Level 1, windows_security/windows_autoplay_disable*

Autoplay is a feature in Windows that can automatically launch an application when you plug in a USB drive, CD or DVD. This can be used by attackers to run malicious code without your consent or knowledge.
## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Command line|user|if((Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun -ErrorAction SilentlyContinue).NoDriveTypeAutoRun -ne 0xFF) { 'Autoplay enabled' } else { '' }|

## Rollback
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Command line|admin|Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun -Type DWord -Value 0xFF -Force|

## Remediation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Command line|admin|Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun -Type DWord -Value 0x91 -Force|

# Built-in Administrator account enabled

## Threat


**Dimension : credentials / Severity : 5**

*Tags : CIS Benchmark Level 1, windows_security/wi_accounts_enableadmin*

The Built-in Administrator account is a powerful account that has full access to the system. Having this account enabled is a security risk as it is a common target for attackers. It should be disabled unless it is absolutely necessary to enable it.
## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Command line|user|if((net user Administrator \| findstr /C:'Account active') -match 'Yes') { 'Administrator account is active' } else { '' }|

## Rollback
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Command line|admin|net user Administrator /active:no|

## Remediation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Command line|admin|net user Administrator /active:yes|

# Windows Firewall disabled

## Threat


**Dimension : network / Severity : 5**

*Tags : CIS Benchmark Level 1, windows_security/win_fw_enable*

Windows Firewall is a built-in feature of Windows that helps to protect your computer from unauthorized access. When it's disabled, your computer is vulnerable to attacks from the network. We recommend that you enable it.
## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Command line|user|if((Get-NetFirewallProfile -All \| Where-Object { $_.Enabled -eq 'False' })) { 'One or more firewall profiles are disabled' } else { '' }|

## Rollback
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Command line|admin|Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True|

## Remediation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Command line|admin|Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False|

# Remote Registry Service enabled

## Threat


**Dimension : system services / Severity : 3**

*Tags : CIS Benchmark Level 1, windows_security/registry_remote_access*

The Remote Registry Service allows remote access to the Windows Registry. This can be a security risk if not properly secured.
## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Command line|user|if((Get-Service -Name RemoteRegistry).Status -eq 'Running') { 'RemoteRegistry service is running' } else { '' }|

## Rollback
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Command line|admin|sc config RemoteRegistry start= disabled && sc stop RemoteRegistry|

## Remediation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Command line|admin|sc config RemoteRegistry start= auto && sc start RemoteRegistry|

# LM and NTLMv1 protocols enabled

## Threat


**Dimension : credentials / Severity : 5**

*Tags : CIS Benchmark Level 1, windows_security/cred_lm_ntlmv1*

The LM and NTLMv1 protocols are outdated and insecure authentication protocols. They should be disabled to prevent potential security threats. Leaving these protocols enabled can allow attackers to potentially crack passwords and gain unauthorized access to sensitive information.
## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 0|Command line|user|if(((Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue).LmCompatibilityLevel -lt 5) -or ((Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -ErrorAction SilentlyContinue).NtlmMinClientSec -lt 537395200) -or ((Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -ErrorAction SilentlyContinue).NtlmMinServerSec -lt 537395200)) { 'Weak NTLM settings' } else { '' }|

## Rollback
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 0|Command line|admin|Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel' -Value '5' -Type DWord; Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'NtlmMinClientSec' -Value '537395200' -Type DWord; Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'NtlmMinServerSec' -Value '537395200' -Type DWord|

## Remediation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 0|Command line|admin|Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel' -Value '1' -Type DWord; Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'NtlmMinClientSec' -Value '262144' -Type DWord; Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'NtlmMinServerSec' -Value '537395200' -Type DWord|

# Lsass.exe process protection not enabled

## Threat


**Dimension : system integrity / Severity : 4**

*Tags : CIS Benchmark Level 1, windows_security/os_lsass_protection*

Lsass.exe is a critical system process that handles user authentication. It contains sensitive information such as passwords and security tokens. If this process is compromised, it could lead to a security breach. Enabling Lsass.exe process protection helps prevent attacks against this process. This content will show you how to enable Lsass.exe process protection.
## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Command line|user|if((Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue).RunAsPPL -eq 0) { 'RunAsPPL is a REG_DWORD with value 0' } else { '' }|

## Rollback
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Command line|user|reg admin 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' /v 'RunAsPPL' /t REG_DWORD /d 1 /f|

## Remediation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Command line|admin|reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v 'RunAsPPL' /t REG_DWORD /d 0 /f|

# PowerShell execution policy not set to RemoteSigned

## Threat


**Dimension : system integrity / Severity : 4**

*Tags : CIS Benchmark Level 1, windows_security/powershell/executionpolicy*

PowerShell is a powerful command-line tool that is built into Windows, and is often used by attackers to carry out malicious activities. The execution policy determines which scripts are allowed to run on a Windows system. If the execution policy is not set to RemoteSigned, it could allow an attacker to run malicious scripts on your system.
## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Command line|user|if((Get-ExecutionPolicy) -ne 'RemoteSigned') { 'Execution Policy not RemoteSigned' } else { '' }|

## Rollback
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Command line|admin|Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Force|

## Remediation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Command line|admin|Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force|
