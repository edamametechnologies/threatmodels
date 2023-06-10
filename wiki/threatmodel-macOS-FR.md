
macOS Threat Model (FR)
=======================

Contents
========

* [Edamame Helper inactif](#edamame-helper-inactif)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
* [Profils MDM installés](#profils-mdm-installs)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
* [Administration à distance JAMF installée](#administration--distance-jamf-installe)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
* [Wake On LAN activé](#wake-on-lan-activ)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
* [Mises à jour Appstore manuelles](#mises--jour-appstore-manuelles)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
* [Pare-feu local désactivé](#pare-feu-local-dsactiv)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
* [Login automatique activé](#login-automatique-activ)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
* [Accès à distance activé](#accs--distance-activ)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
* [Bureau à distance activé](#bureau--distance-activ)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
* [Partage de fichiers activé](#partage-de-fichiers-activ)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
* [Événements à distance activés](#vnements--distance-activs)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
* [Clé d'entreprise de récupération de disque](#cl-dentreprise-de-rcupration-de-disque)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
* [Encryption du disque désactivée](#encryption-du-disque-dsactive)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
* [Applications non signées autorisées](#applications-non-signes-autorises)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
* [Mises à jour système manuelles](#mises--jour-systme-manuelles)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
* [Réponse au ping activée](#rponse-au-ping-active)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
* [Ecran protégé désactivé](#ecran-protg-dsactiv)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
* [Pas d'antivirus installé](#pas-dantivirus-install)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
* [Protection d'intégrité système désactivée](#protection-dintgrit-systme-dsactive)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
* [Compte invité activé](#compte-invit-activ)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
* [Utilisateur root activé](#utilisateur-root-activ)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
* [Changement de paramètres système non protégés](#changement-de-paramtres-systme-non-protgs)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
* [Apple ID compromise](#apple-id-compromise)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
* [Votre OS n'est pas à jour](#votre-os-nest-pas--jour)
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
|macOS 12|Ligne de commande|admin|ps -ef \| grep edamame_helper \| grep -v grep > /dev/null \|\| echo nohelper|

## Retour en arrière
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Ligne de commande|user|https://edamamecompany.sharepoint.com/:u:/s/Anyone/EW70U3YGjwdFryyIzVo3maMBNE6XAb0ZabQ0Bi0uAw5vsQ?e=7kVnf4|

## Remédiation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Ligne de commande|system|/Library/Application\ Support/Edamame/Edamame-Helper/uninstall.sh|

# Profils MDM installés

## Menace


**Dimension : system integrity / Sévérité : 5**

Un ou plusieurs profils de gestion des appareils mobiles (MDM) sont installés sur votre ordinateur. Cela signifie que votre ordinateur est, ou peut être, administré à distance par un tiers. S'il s'agit de votre ordinateur personnel, il s'agit d'une grave menace et les profils doivent être supprimés.
## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Ligne de commande|system|profiles list \| grep profileIdentifier|

## Retour en arrière
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Ligne de commande|system|profiles remove -all|

## Remédiation


https://fr.wikipedia.org/wiki/Mobile_device_management
# Administration à distance JAMF installée

## Menace


**Dimension : system integrity / Sévérité : 5**

Votre ordinateur est, ou peut être, administré à distance par un tiers à l'aide du framework JAMF MDM. S'il s'agit de votre ordinateur personnel, il s'agit d'une grave menace et JAMF doit être supprimé.
## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Ligne de commande|admin|pgrep jamf|

## Retour en arrière
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Ligne de commande|system|jamf removeFramework|

## Remédiation


https://www.jamf.com/fr
# Wake On LAN activé

## Menace


**Dimension : network / Sévérité : 1**

*Tags : CIS Benchmark Level 1, macos_security/sysprefs_wake_network_access_disable*

Wake on LAN est une fonctionnalité qui peut réveiller automatiquement votre ordinateur lorsque quelque chose tente de s'y connecter. Ce n'est pas quelque chose dont vous avez besoin dans la plupart des cas et cela peut permettre à un malfrat de se connecter à votre ordinateur à tout moment.
## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Ligne de commande|system|systemsetup getwakeonnetworkaccess \| grep -v Off|

## Retour en arrière
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Ligne de commande|system|systemsetup -setwakeonnetworkaccess off|

## Remédiation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Ligne de commande|system|systemsetup -setwakeonnetworkaccess on|

# Mises à jour Appstore manuelles

## Menace


**Dimension : applications / Sévérité : 3**

*Tags : CIS Benchmark Level 1, macos_security/sysprefs_software_update_app_update_enforce*

Les applications sont constamment mises à jour pour résoudre les problèmes de sécurité potentiels. Il est dans votre intérêt d'obtenir les mises à jour dès que possible grâce aux mises à jour automatiques.
## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Ligne de commande|admin|defaults read /Library/Preferences/com.apple.commerce.plist AutoUpdate 2>&1 \| grep -v 1|

## Retour en arrière
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Ligne de commande|system|defaults write /Library/Preferences/com.apple.commerce.plist AutoUpdate -bool true; defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallAppUpdates -bool true|

## Remédiation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Ligne de commande|system|defaults write /Library/Preferences/com.apple.commerce.plist AutoUpdate -bool false; defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallAppUpdates -bool false|

# Pare-feu local désactivé

## Menace


**Dimension : network / Sévérité : 2**

*Tags : CIS Benchmark Level 1, macos_security/sysprefs_firewall_enable*

Votre pare-feu local est désactivé. C'est bien dans un environnement de confiance mais dangereux si vous vous connectez à des réseaux publics. Vous devriez l'activer par défaut.
## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Ligne de commande|admin|defaults read /Library/Preferences/com.apple.alf globalstate \| grep 0|

## Retour en arrière
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Ligne de commande|system|defaults write /Library/Preferences/com.apple.alf globalstate -int 2|

## Remédiation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Ligne de commande|system|defaults write /Library/Preferences/com.apple.alf globalstate -int 0|

# Login automatique activé

## Menace


**Dimension : credentials / Sévérité : 4**

*Tags : CIS Benchmark Level 1, macos_security/sysprefs_automatic_login_disable*

La connexion automatique peut sembler très pratique mais en fait c'est une menace majeure pour la sécurité : elle permet à n'importe qui d'accéder à vos données sans connaître votre mot de passe.
## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Ligne de commande|user|defaults read /Library/Preferences/com.apple.loginwindow \| grep autoLoginUser|

## Retour en arrière
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Ligne de commande|system|defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser|

## Remédiation

# Accès à distance activé

## Menace


**Dimension : system integrity / Sévérité : 4**

*Tags : CIS Benchmark Level 1, macos_security/sysprefs_ssh_disable*

L'accès à distance est activée. Ce n'est pas nécessaire sauf si vous êtes un professionnel de l'informatique. Ceci est inhabituel et dangereux pour la plupart des utilisateurs.
## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Ligne de commande|system|systemsetup -getremotelogin \| grep On|

## Retour en arrière
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Ligne de commande|fulldisk|echo yes \| systemsetup -setremotelogin off|

## Remédiation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Ligne de commande|fulldisk|systemsetup -setremotelogin on|

# Bureau à distance activé

## Menace


**Dimension : system integrity / Sévérité : 4**

*Tags : CIS Benchmark Level 1, macos_security/sysprefs_remote_management_disable*

La connexion au bureau à distance est activée. Ce n'est pas nécessaire sauf si vous êtes un professionnel de l'informatique. Ceci est inhabituel et dangereux pour la plupart des utilisateurs.
## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Ligne de commande|admin|pgrep ARDAgent|

## Retour en arrière
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Ligne de commande|system|/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -deactivate -configure -access -off|

## Remédiation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Ligne de commande|system|/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -restart -agent|

# Partage de fichiers activé

## Menace


**Dimension : system services / Sévérité : 4**

*Tags : CIS Benchmark Level 1, macos_security/sysprefs_smbd_disable*

Le partage de fichiers est activé. Bien que cela puisse être intentionnel, nous vous recommandons fortement de le désactiver. Ce n'est pas si facile à configurer et cela peut exposer vos données à des personnes indésirables.
## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Ligne de commande|admin|pgrep smbd|

## Retour en arrière
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Ligne de commande|system|launchctl unload -w /System/Library/LaunchDaemons/com.apple.smbd.plist|

## Remédiation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Ligne de commande|system|launchctl load -w /System/Library/LaunchDaemons/com.apple.smbd.plist; defaults write /Library/Preferences/SystemConfiguration/com.apple.smb.server.plist EnabledServices -array disk|

# Événements à distance activés

## Menace


**Dimension : system integrity / Sévérité : 4**

*Tags : CIS Benchmark Level 1, macos_security/sysprefs_rae_disable*

Les événements à distance sont activés. Bien que cela puisse être intentionnel, nous vous recommandons fortement de les désactiver. C'est inutile pour la plupart des utilisateurs et cela a été une cible d'attaques dans un passé récent.
## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Ligne de commande|system|launchctl print-disabled system \| grep com.apple.AEServer \| grep false|

## Retour en arrière
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Ligne de commande|fulldisk|systemsetup -setremoteappleevents off|

## Remédiation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Ligne de commande|fulldisk|systemsetup -setremoteappleevents on|

# Clé d'entreprise de récupération de disque

## Menace


**Dimension : system integrity / Sévérité : 4**

Il semble que le disque dur de votre ordinateur ait été crypté par votre employeur. Cela signifie qu'ils pourraient potentiellement le déchiffrer si vous leur rendez l'ordinateur. Vous devriez supprimer cette possibilité.
## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Ligne de commande|system|fdesetup hasinstitutionalrecoverykey \| grep true|

## Retour en arrière


https://derflounder-wordpress-com.translate.goog/2019/07/03/managing-macos-mojaves-filevault-2-with-fdesetup/?_x_tr_sl=auto&_x_tr_tl=fr&_x_tr_hl=en&_x_tr_pto=wapp
## Remédiation


https://derflounder-wordpress-com.translate.goog/2019/07/03/managing-macos-mojaves-filevault-2-with-fdesetup/?_x_tr_sl=auto&_x_tr_tl=fr&_x_tr_hl=en&_x_tr_pto=wapp
# Encryption du disque désactivée

## Menace


**Dimension : system services / Sévérité : 4**

*Tags : CIS Benchmark Level 1, macos_security/sysprefs_filevault_enforce*

Votre stockage principal n'est pas crypté. Bien qu'il y ait un petit impact sur les performances en l'activant, nous vous invitons vraiment à le configurer. Sans cela, toute personne accédant physiquement à votre ordinateur peut accéder à vos données.
## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Ligne de commande|admin|fdesetup isactive \| grep false|

## Retour en arrière


https://www.youtube.com/watch?v=Ovr9nyIagTY
## Remédiation


https://www.youtube.com/watch?v=Ovr9nyIagTY
# Applications non signées autorisées

## Menace


**Dimension : applications / Sévérité : 4**

*Tags : CIS Benchmark Level 1, macos_security/os_gatekeeper_enable*

Votre ordinateur a été configuré pour autoriser l'exécution d'applications non signées. C'est inhabituel et dangereux. Vous devriez désactiver cette option.
## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Ligne de commande|admin|spctl --status \| grep disabled|

## Retour en arrière
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Ligne de commande|system|spctl --global-enable|

## Remédiation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Ligne de commande|system|spctl --global-disable|

# Mises à jour système manuelles

## Menace


**Dimension : system integrity / Sévérité : 4**

*Tags : CIS Benchmark Level 1, macos_security/sysprefs_install_macos_updates_enforce, macos_security/sysprefs_software_update_download_enforce*

Les mises à jour du système sont manuelles. Vous devriez vraiment activer les mises à jour automatiques du système pour obtenir les derniers correctifs de sécurité pour votre ordinateur.
## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Ligne de commande|admin|defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates 2>&1 \| grep -v 1|

## Retour en arrière
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Ligne de commande|system|defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true; defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool true; defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -bool true; defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true; defaults write /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall -bool true; softwareupdate --schedule on|

## Remédiation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Ligne de commande|system|defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool false; defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool false; defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -bool false; defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool false; defaults write /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall -bool false; softwareupdate --schedule off|

# Réponse au ping activée

## Menace


**Dimension : network / Sévérité : 3**

*Tags : CIS Benchmark Level 1, macos_security/sysprefs_firewall_stealth_mode_enable*

Votre ordinateur répondra si quelque chose essaie de vérifier sa présence. Cela peut être très mauvais et permettre à quiconque de vérifier votre présence sur un réseau et éventuellement d'attaquer votre ordinateur....
## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Ligne de commande|admin|/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode \| grep disabled|

## Retour en arrière
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Ligne de commande|system|/usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on|

## Remédiation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Ligne de commande|system|/usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode off|

# Ecran protégé désactivé

## Menace


**Dimension : credentials / Sévérité : 3**

*Tags : CIS Benchmark Level 1, macos_security/sysprefs_screensaver_ask_for_password_delay_enforce*

Votre ordinateur n'a pas d'économiseur d'écran activé avec un mot de passe. Il le laisse ouvert à l'accès physique par n'importe qui. C'est très dangereux !
## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Ligne de commande|user|sysadminctl -screenLock status 2>&1 \| grep off|

## Retour en arrière


https://www.youtube.com/watch?v=C6of13nZTpM
## Remédiation


https://www.youtube.com/watch?v=C6of13nZTpM
# Pas d'antivirus installé

## Menace


**Dimension : applications / Sévérité : 4**

Vous n'avez pas d'antivirus installé. Nous vous recommandons d'en installer un.
## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Ligne de commande|admin|pgrep RTProtectionDaemon >/dev/null \|\| echo noepp|

## Retour en arrière


https://www.malwarebytes.com/
## Remédiation


https://support.malwarebytes.com/hc/en-us/articles/360039023473-Uninstall-and-reinstall-Malwarebytes-using-the-Malwarebytes-Support-Tool
# Protection d'intégrité système désactivée

## Menace


**Dimension : system integrity / Sévérité : 5**

*Tags : CIS Benchmark Level 1, macos_security/os_sip_enable*

La Protection de l'Intégrité du Système est une capacité clé de macOS qui empêche tous logiciels de modifier les fichiers et les composants du système. Dans une certaine mesure, c'est un antivirus "assez bon" pour votre Mac. Le désactiver est... inhabituel et dangereux. Il devrait être activé par défaut sur votre Mac. Ce contenu vous expliquera comment l'activer à nouveau. Soyez courageux... c'est un peu difficile à réaliser !
## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Ligne de commande|user|csrutil status \| grep disabled|

## Retour en arrière


https://www.remosoftware.com/info/fr/comment-activer-ou-desactiver-la-protection-de-lintegrite-du-systeme-mac/
## Remédiation

# Compte invité activé

## Menace


**Dimension : system services / Sévérité : 2**

*Tags : CIS Benchmark Level 1, macos_security/sysprefs_guest_account_disable*

Le compte invité est activé. C'est généralement bien, mais il n'est pas si facile de limiter l'accès à vos données. Vous devriez le désactiver.
## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Ligne de commande|user|sysadminctl -guestAccount status 2>&1 \| grep enabled|

## Retour en arrière
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Ligne de commande|system|sysadminctl -guestAccount off|

## Remédiation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Ligne de commande|system|sysadminctl -guestAccount on|

# Utilisateur root activé

## Menace


**Dimension : system integrity / Sévérité : 3**

Un utilisateur système spécial a été configuré sur votre ordinateur. Ceci est inhabituel et doit être désactivé immédiatement.
## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Ligne de commande|user|dscl . -read /Users/root Password \| grep "\*\*"|

## Retour en arrière


https://www.youtube.com/watch?v=Bw05ksrrD4g
## Remédiation


https://www.youtube.com/watch?v=Bw05ksrrD4g
# Changement de paramètres système non protégés

## Menace


**Dimension : system integrity / Sévérité : 3**

*Tags : CIS Benchmark Level 1, macos_security/sysprefs_system_wide_preferences_configure*

Les paramètres de votre système informatique peuvent être modifiés par tous les utilisateurs. Vous devriez le restreindre.
## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Ligne de commande|user|security authorizationdb read system.preferences 2> /dev/null \| grep -A1 shared \| grep true|

## Retour en arrière
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Ligne de commande|system|security authorizationdb read system.preferences > /tmp/system.preferences.plist; /usr/libexec/PlistBuddy -c "Set :shared false" /tmp/system.preferences.plist; security authorizationdb write system.preferences < /tmp/system.preferences.plist|

## Remédiation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Ligne de commande|system|security authorizationdb read system.preferences > /tmp/system.preferences.plist; /usr/libexec/PlistBuddy -c "Set :shared true" /tmp/system.preferences.plist; security authorizationdb write system.preferences < /tmp/system.preferences.plist|

# Apple ID compromise

## Menace


**Dimension : credentials / Sévérité : 1**

Votre e-mail Apple ID est apparue récemment dans une fuite de données, veuillez examiner la fuite et modifier vos mots de passe en conséquence.
## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Ligne de commande|user|pwned -i 365|

## Retour en arrière
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Ligne de commande||digitalidentity_manager|

## Remédiation


https://haveibeenpwned.com/
# Votre OS n'est pas à jour

## Menace


**Dimension : system integrity / Sévérité : 2**

Votre système d'exploitation n'est pas à jour, veuillez procéder à sa mise à niveau afin d'obtenir les derniers correctifs de sécurité.
## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|macOS 12|Ligne de commande|admin|defaults read /Library/Preferences/com.apple.SoftwareUpdate.plist \| grep macOS|

## Retour en arrière


https://www.youtube.com/watch?v=FG2DXkPA93g&t=124s
## Remédiation


https://www.youtube.com/watch?v=FG2DXkPA93g&t=124s