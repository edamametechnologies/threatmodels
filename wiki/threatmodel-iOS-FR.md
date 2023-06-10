
iOS Threat Model (FR)
=====================

Contents
========

* [Profils MDM installés](#profils-mdm-installs)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
* [Ecran protégé désactivé](#ecran-protg-dsactiv)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
* [Votre appareil est jailbreaké](#votre-appareil-est-jailbreak)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
* [Apple ID compromise](#apple-id-compromise)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
* [Application pas à jour](#application-pas--jour)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
* [Votre OS n'est pas à jour](#votre-os-nest-pas--jour)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)

# Profils MDM installés

## Menace


**Dimension : system integrity / Sévérité : 5**

Un ou plusieurs profils de gestion des appareils mobiles (MDM) sont installés sur votre ordinateur. Cela signifie que votre appareil est, ou peut être, administré à distance par un tiers. S'il s'agit de votre appareil personnel, il s'agit d'une grave menace et les profils doivent être supprimés.
## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|iOS 15|Ligne de commande|user|mdm_check|

## Retour en arrière


https://fr.wikipedia.org/wiki/Mobile_device_management
## Remédiation


https://fr.wikipedia.org/wiki/Mobile_device_management
# Ecran protégé désactivé

## Menace


**Dimension : credentials / Sévérité : 3**

Votre appareil n'a pas d'économiseur d'écran activé avec un mot de passe. Il le laisse ouvert à l'accès physique par n'importe qui. C'est très dangereux !
## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|iOS 15|Ligne de commande|user|screenlock_check|

## Retour en arrière


https://www.youtube.com/watch?v=55lKpx3SCK0
## Remédiation


https://www.youtube.com/watch?v=55lKpx3SCK0
# Votre appareil est jailbreaké

## Menace


**Dimension : system integrity / Sévérité : 5**

Votre appareil est jailbreaké. Soit vous l'avez fait vous-même, soit un acteur malveillant l'a fait pour accéder à vos données personnel. C'est très dangereux ! Vous devez restaurer votre appareil aux paramètres d'usine.
## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|iOS 15|Ligne de commande|user|jailbreak_check|

## Retour en arrière


https://www.youtube.com/watch?v=jdIrJ2ex0gE
## Remédiation


https://www.youtube.com/watch?v=jdIrJ2ex0gE
# Apple ID compromise

## Menace


**Dimension : credentials / Sévérité : 4**

Votre e-mail Apple ID est apparue récemment dans une fuite de données référencée sur haveibeenpwned.com, veuillez examiner la fuite et modifier vos mots de passe en conséquence.
## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|iOS 15|Ligne de commande|user|pwned -i 365|

## Retour en arrière
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|iOS 15|Ligne de commande||digitalidentity_manager|

## Remédiation


https://www.futura-sciences.com/tech/actualites/internet-voici-savoir-si-vos-donnees-personnelles-internet-ont-ete-piratees-103095/
# Application pas à jour

## Menace


**Dimension : applications / Sévérité : 3**

Cette application n'est pas à jour. Les applications sont constamment mises à jour pour résoudre les problèmes de sécurité potentiels. Il est dans votre intérêt d'obtenir les mises à jour dès que possible grâce aux mises à jour automatiques.
## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|iOS 15|Ligne de commande|user|latestapp_check|

## Retour en arrière


https://www.youtube.com/shorts/ALRMvPnUTt0
## Remédiation


https://www.youtube.com/watch?v=FG2DXkPA93g&t=124s
# Votre OS n'est pas à jour

## Menace


**Dimension : system integrity / Sévérité : 3**

Votre système d'exploitation n'est pas à jour, veuillez procéder à sa mise à niveau afin d'obtenir les derniers correctifs de sécurité.
## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|iOS 15|Ligne de commande|user|latestos_check|

## Retour en arrière


https://www.youtube.com/watch?v=02UHT0OBGlo
## Remédiation


https://www.youtube.com/watch?v=02UHT0OBGlo