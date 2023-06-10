
Windows Threat Model (FR)
=========================

Contents
========

* [Edamame Helper inactif](#edamame-helper-inactif)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
* [Windows Defender désactivé](#windows-defender-dsactiv)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
* [Mises à jour automatiques des applications du Windows Store désactivées](#mises--jour-automatiques-des-applications-du-windows-store-dsactives)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
* [Contrôle de compte d'utilisateur désactivé](#contrle-de-compte-dutilisateur-dsactiv)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
* [Protocole SMBv1 activé](#protocole-smbv1-activ)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
* [Connexion automatique activée](#connexion-automatique-active)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
* [Windows Script Host activé](#windows-script-host-activ)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
* [Protocole de Bureau à distance (RDP) activé](#protocole-de-bureau--distance-rdp-activ)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
* [Mise à jour Windows désactivée](#mise--jour-windows-dsactive)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
* [Compte Invité activé](#compte-invit-activ)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
* [Lecture automatique activée](#lecture-automatique-active)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
* [Compte administrateur intégré activé](#compte-administrateur-intgr-activ)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
* [Pare-feu Windows désactivé](#pare-feu-windows-dsactiv)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
* [Service Registre distant activé](#service-registre-distant-activ)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
* [Protection du processus Lsass.exe désactivée](#protection-du-processus-lsassexe-dsactive)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
* [La stratégie d'exécution de PowerShell n'est pas définie sur RemoteSigned](#la-stratgie-dexcution-de-powershell-nest-pas-dfinie-sur-remotesigned)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)

# Edamame Helper inactif

## Menace


**Dimension : system services / Sévérité : 5**

Le logiciel d'assistance d'Edamame n'est pas en cours d'exécution ou a besoin d'être mis à jour. Il est requis pour une analyse complète du score de sécurité.
## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 12|Ligne de commande|user|$result = if ((Get-Service -Name edamame_helper -ErrorAction SilentlyContinue).Status -eq 'Running') { "" } else { "no helper" }; $result
|

## Retour en arrière
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 12|Ligne de commande|user|https://edamamecompany.sharepoint.com/:u:/s/Anyone/EY31rA1xkKpIpnvVrz95Zv4BGesgmjBSl9xuzCZx6hDk8w?e=rlaNKz|

## Remédiation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 12|Ligne de commande|user|h|

## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Ligne de commande|user|if(((Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI' -Name 'DisablePasswordCaching' -ErrorAction SilentlyContinue).DisablePasswordCaching) -eq 1) { 'Password caching is disabled' } else { '' }|

## Retour en arrière
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Ligne de commande|admin|reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI' /v DisablePasswordCaching /t REG_DWORD /d 1 /f|

## Remédiation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Ligne de commande|admin|reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI' /v DisablePasswordCaching /t REG_DWORD /d 0 /f|

# Windows Defender désactivé

## Menace


**Dimension : applications / Sévérité : 5**

*Tags : CIS Benchmark Level 1, windows_security/wd_disabled*

Windows Defender est un logiciel antivirus et antimalware intégré à Windows. Le désactiver peut laisser votre système vulnérable à diverses menaces, telles que des virus, des chevaux de Troie et des logiciels espions.
## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Ligne de commande|user|if((Get-MpPreference \| Select-Object -ExpandProperty DisableRealtimeMonitoring) -eq $true) { 'Real-time monitoring is disabled' } else { '' }|

## Retour en arrière
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Ligne de commande|admin|Set-MpPreference -DisableRealtimeMonitoring $false|

## Remédiation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Ligne de commande|admin|Set-MpPreference -DisableRealtimeMonitoring $true|

# Mises à jour automatiques des applications du Windows Store désactivées

## Menace


**Dimension : system services / Sévérité : 3**

*Tags : CIS Benchmark Level 1, windows_10_1709*

Les mises à jour automatiques des applications du Windows Store sont désactivées, ce qui peut entraîner des applications obsolètes et représenter un risque pour la sécurité. Il est recommandé d'activer les mises à jour automatiques des applications du Windows Store.
## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|windows 10|Ligne de commande|user|if((Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore' -ErrorAction SilentlyContinue).AutoDownload -ne 4) { 'Automatic updates of App store apps disabled' } else { '' }|

## Retour en arrière
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|windows 10|Ligne de commande|admin|reg add 'HKLM\SOFTWARE\Policies\Microsoft\WindowsStore' /v AutoDownload /t REG_DWORD /d 4 /f|

## Remédiation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|windows 10|Ligne de commande|admin|reg add 'HKLM\SOFTWARE\Policies\Microsoft\WindowsStore' /v AutoDownload /t REG_DWORD /d 2 /f|

# Contrôle de compte d'utilisateur désactivé

## Menace


**Dimension : system integrity / Sévérité : 5**

*Tags : CIS Benchmark Level 2, windows_security/uac_enable*

Le Contrôle de compte d'utilisateur (UAC) est une fonctionnalité de sécurité dans Windows qui aide à prévenir les modifications non autorisées sur votre ordinateur. Si UAC est désactivé, il est plus facile pour les logiciels malveillants de faire des changements sur votre système sans votre connaissance. Vous devez activer UAC pour protéger votre système contre de telles attaques.
## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Ligne de commande|user|if((Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue).EnableLUA -eq 0) { 'UAC disabled' } else { '' }|

## Retour en arrière
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Ligne de commande|admin|Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1 -Type DWord|

## Remédiation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Ligne de commande|admin|Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 0 -Type DWord|

# Protocole SMBv1 activé

## Menace


**Dimension : network / Sévérité : 5**

*Tags : CIS Benchmark Level 1, windows_security/smb1_protocol_disabled*

Le protocole SMBv1 est activé sur votre système. Ce protocole est obsolète et présente des vulnérabilités connues qui peuvent permettre aux attaquants de prendre le contrôle de votre système. Il devrait être désactivé pour améliorer la sécurité de votre système.
## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Ligne de commande|user|if((Get-SmbServerConfiguration).EnableSMB1Protocol -eq $true) { 'SMBv1 enabled' } else { '' }|

## Retour en arrière
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Ligne de commande|admin|Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol|

## Remédiation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Ligne de commande|admin|Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol|

# Connexion automatique activée

## Menace


**Dimension : credentials / Sévérité : 4**

La connexion automatique permet au système de connecter automatiquement un utilisateur après le démarrage. Cela peut être un risque pour la sécurité si le système n'est pas physiquement sécurisé car n'importe qui peut accéder au système sans fournir de credentials. Il est recommandé de désactiver la connexion automatique.
## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Ligne de commande|user|if((Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue).AutoAdminLogon -eq '1') { 'Automatic logon enabled' } else { '' }|

## Retour en arrière
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Ligne de commande|admin|Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon -Value 0|

## Remédiation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Ligne de commande|admin|Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon -Value 1|

# Windows Script Host activé

## Menace


**Dimension : system integrity / Sévérité : 4**

*Tags : CIS Benchmark Level 1, windows_security/disable_wscript_host*

Windows Script Host est un environnement de script Windows intégré qui permet l'exécution de VBScript, JScript et d'autres langages de script. Le désactiver peut aider à atténuer certains types d'attaques de logiciels malveillants.
## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Ligne de commande|user|if((Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' -Name Enabled -ErrorAction SilentlyContinue).Enabled -eq 1) { 'Windows Script Host enabled' } else { '' }|

## Retour en arrière
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Ligne de commande|admin|reg add 'HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings' /v Enabled /t REG_DWORD /d 0 /f|

## Remédiation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Ligne de commande|admin|reg add 'HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings' /v Enabled /t REG_DWORD /d 1 /f|

# Protocole de Bureau à distance (RDP) activé

## Menace


**Dimension : network / Sévérité : 4**

*Tags : CIS Benchmark Level 1, windows_security/rdp_enable*

RDP permet aux utilisateurs d'accéder à distance et de contrôler un ordinateur Windows à partir d'un autre emplacement. Bien que cela puisse être pratique, cela présente également un risque de sécurité important s'il est laissé activé et non protégé. Un attaquant pourrait potentiellement accéder à votre ordinateur et compromettre vos données sensibles ou même prendre le contrôle de votre système.
## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Ligne de commande|user|if((Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction SilentlyContinue) -eq 0) { 'Terminal Services connections allowed' } else { '' }|

## Retour en arrière
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Ligne de commande|admin|Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 1|

## Remédiation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Ligne de commande|admin|Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0|

# Mise à jour Windows désactivée

## Menace


**Dimension : system integrity / Sévérité : 5**

*Tags : CIS Benchmark Level 1, windows_security/update_automatic_updates*

La désactivation de la mise à jour de Windows empêche l'installation des correctifs et des mises à jour de sécurité critiques sur votre système, laissant votre système vulnérable aux exploits et menaces connus. Il est fortement recommandé d'activer la mise à jour de Windows pour garantir que votre système est à jour avec les derniers correctifs de sécurité.
## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Ligne de commande|user|if((Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name NoAutoUpdate -ErrorAction SilentlyContinue) -ne $null) { 'NoAutoUpdate is set' } else { '' }|

## Retour en arrière
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Ligne de commande|admin|reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' /v NoAutoUpdate /t REG_DWORD /d 0 /f|

## Remédiation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Ligne de commande|admin|reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' /v NoAutoUpdate /t REG_DWORD /d 1 /f|

# Compte Invité activé

## Menace


**Dimension : credentials / Sévérité : 4**

*Tags : CIS Benchmark Level 1, windows_security/accounts_guest_account*

Le compte Invité est un compte par défaut dans Windows, qui permet aux utilisateurs d'accéder au système avec des privilèges limités. Il est recommandé de désactiver ce compte pour empêcher tout accès non autorisé à votre système et à vos données.
## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Ligne de commande|user|if((Get-WmiObject -Class Win32_UserAccount \| Where-Object {$_.Name -eq 'Guest'} \| Select-Object -Property Name).Name -eq 'Guest') { 'Guest account exists' } else { '' }|

## Retour en arrière
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Ligne de commande|admin|Disable-LocalUser -Name Guest|

## Remédiation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Ligne de commande|admin|Enable-LocalUser -Name Guest|

# Lecture automatique activée

## Menace


**Dimension : system services / Sévérité : 3**

*Tags : CIS Benchmark Level 1, windows_security/windows_autoplay_disable*

La lecture automatique est une fonctionnalité de Windows qui peut lancer automatiquement une application lorsque vous branchez une clé USB, un CD ou un DVD. Cela peut être utilisé par des attaquants pour exécuter un code malveillant sans votre consentement ni votre connaissance.
## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Ligne de commande|user|if((Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun -ErrorAction SilentlyContinue).NoDriveTypeAutoRun -ne 0xFF) { 'Autoplay enabled' } else { '' }|

## Retour en arrière
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Ligne de commande|admin|Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun -Type DWord -Value 0xFF -Force|

## Remédiation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Ligne de commande|admin|Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun -Type DWord -Value 0x91 -Force|

# Compte administrateur intégré activé

## Menace


**Dimension : credentials / Sévérité : 5**

*Tags : CIS Benchmark Level 1, windows_security/wi_accounts_enableadmin*

Le compte administrateur intégré est un compte puissant qui a un accès complet au système. Avoir ce compte activé représente un risque de sécurité car c'est une cible courante pour les attaquants. Il devrait être désactivé sauf s'il est absolument nécessaire de l'activer.
## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Ligne de commande|user|if((net user Administrator \| findstr /C:'Account active') -match 'Yes') { 'Administrator account is active' } else { '' }|

## Retour en arrière
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Ligne de commande|admin|net user Administrator /active:no|

## Remédiation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Ligne de commande|admin|net user Administrator /active:yes|

# Pare-feu Windows désactivé

## Menace


**Dimension : network / Sévérité : 5**

*Tags : CIS Benchmark Level 1, windows_security/win_fw_enable*

Le pare-feu Windows est une fonctionnalité intégrée de Windows qui aide à protéger votre ordinateur contre les accès non autorisés. Lorsqu'il est désactivé, votre ordinateur est vulnérable aux attaques en provenance du réseau. Nous vous recommandons de l'activer.
## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Ligne de commande|user|if((Get-NetFirewallProfile -All \| Where-Object { $_.Enabled -eq 'False' })) { 'One or more firewall profiles are disabled' } else { '' }|

## Retour en arrière
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Ligne de commande|admin|Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True|

## Remédiation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Ligne de commande|admin|Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False|

# Service Registre distant activé

## Menace


**Dimension : system services / Sévérité : 3**

*Tags : CIS Benchmark Level 1, windows_security/registry_remote_access*

Le Service Registre distant permet l'accès distant au Registre de Windows. Cela peut être un risque de sécurité si cela n'est pas correctement sécurisé.
## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Ligne de commande|user|if((Get-Service -Name RemoteRegistry).Status -eq 'Running') { 'RemoteRegistry service is running' } else { '' }|

## Retour en arrière
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Ligne de commande|admin|sc config RemoteRegistry start= disabled && sc stop RemoteRegistry|

## Remédiation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Ligne de commande|admin|sc config RemoteRegistry start= auto && sc start RemoteRegistry|

## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 0|Ligne de commande|user|if(((Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue).LmCompatibilityLevel -lt 5) -or ((Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -ErrorAction SilentlyContinue).NtlmMinClientSec -lt 537395200) -or ((Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -ErrorAction SilentlyContinue).NtlmMinServerSec -lt 537395200)) { 'Weak NTLM settings' } else { '' }|

## Retour en arrière
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 0|Ligne de commande|admin|Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel' -Value '5' -Type DWord; Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'NtlmMinClientSec' -Value '537395200' -Type DWord; Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'NtlmMinServerSec' -Value '537395200' -Type DWord|

## Remédiation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 0|Ligne de commande|admin|Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel' -Value '1' -Type DWord; Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'NtlmMinClientSec' -Value '262144' -Type DWord; Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'NtlmMinServerSec' -Value '537395200' -Type DWord|

# Protection du processus Lsass.exe désactivée

## Menace


**Dimension : system integrity / Sévérité : 4**

*Tags : CIS Benchmark Level 1, windows_security/os_lsass_protection*

Lsass.exe est un processus système essentiel qui gère l'authentification de l'utilisateur. Il contient des informations sensibles telles que des mots de passe et des jetons de sécurité. Si ce processus est compromis, cela peut entraîner une violation de sécurité. L'activation de la protection du processus Lsass.exe aide à prévenir les attaques contre ce processus. Ce contenu vous montrera comment activer la protection du processus Lsass.exe.
## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Ligne de commande|user|if((Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue).RunAsPPL -eq 0) { 'RunAsPPL is a REG_DWORD with value 0' } else { '' }|

## Retour en arrière
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Ligne de commande|user|reg admin 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' /v 'RunAsPPL' /t REG_DWORD /d 1 /f|

## Remédiation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Ligne de commande|admin|reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v 'RunAsPPL' /t REG_DWORD /d 0 /f|

# La stratégie d'exécution de PowerShell n'est pas définie sur RemoteSigned

## Menace


**Dimension : system integrity / Sévérité : 4**

*Tags : CIS Benchmark Level 1, windows_security/powershell/executionpolicy*

PowerShell est un outil en ligne de commande puissant intégré à Windows, souvent utilisé par des attaquants pour effectuer des activités malveillantes. La stratégie d'exécution détermine les scripts autorisés à s'exécuter sur un système Windows. Si la stratégie d'exécution n'est pas définie sur RemoteSigned, cela pourrait permettre à un attaquant d'exécuter des scripts malveillants sur votre système.
## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Ligne de commande|user|if((Get-ExecutionPolicy) -ne 'RemoteSigned') { 'Execution Policy not RemoteSigned' } else { '' }|

## Retour en arrière
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Ligne de commande|admin|Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Force|

## Remédiation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Windows 10|Ligne de commande|admin|Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force|
