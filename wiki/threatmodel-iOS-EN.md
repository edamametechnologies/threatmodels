
iOS Threat Model (EN)
=====================

Contents
========

* [MDM profiles installed](#mdm-profiles-installed)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [Screen lock disabled](#screen-lock-disabled)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [Your device is jailbroken](#your-device-is-jailbroken)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [Compromised Apple ID](#compromised-apple-id)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [App is not up to date](#app-is-not-up-to-date)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [Your OS is not up to date](#your-os-is-not-up-to-date)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)

# MDM profiles installed

## Threat


**Dimension : system integrity / Severity : 5**

You have one or more Mobile Device Management (MDM) profiles installed on your computer. This means that your device is or can be remotely administered by a 3rd party. If this is your personal device, this is a grave threat and the profiles should be removed.
## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|iOS 15|Command line|user|mdm_check|

## Rollback


https://en.wikipedia.org/wiki/Mobile_device_managements
## Remediation


https://en.wikipedia.org/wiki/Mobile_device_managements
# Screen lock disabled

## Threat


**Dimension : credentials / Severity : 3**

Your device doesn't have a screensaver enabled with a password. It leaves it open for phsyical access by anyone. This is very dangerous!
## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|iOS 15|Command line|user|screenlock_check|

## Rollback


https://www.youtube.com/watch?v=2t0NrqIwI2s
## Remediation


https://www.youtube.com/watch?v=2t0NrqIwI2s
# Your device is jailbroken

## Threat


**Dimension : system integrity / Severity : 5**

Your device is jailbroken. Either you did it yourself or a bad actor did it to access your personal data. This is very dangerous! You need to restore your device to factory settings.
## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|iOS 15|Command line|user|jailbreak_check|

## Rollback


https://www.youtube.com/watch?v=_VNsH_OWmRw
## Remediation


https://www.youtube.com/watch?v=_VNsH_OWmRw
# Compromised Apple ID

## Threat


**Dimension : credentials / Severity : 4**

Your Apple ID email has recently appeared in a data breach referenced on haveibeenpwned.com, please review the breach and change your passwords accordingly.
## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|iOS 15|Command line|user|pwned -i 365|

## Rollback
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|iOS 15|Command line||digitalidentity_manager|

## Remediation


https://en.wikipedia.org/wiki/Have_I_Been_Pwned
# App is not up to date

## Threat


**Dimension : applications / Severity : 3**

This app is not up to date. Applications are constantly updated to fix potential security issues. It's your best interest to get updates as soon as you can through automatic updates.
## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|iOS 15|Command line|user|latestapp_check|

## Rollback


https://www.youtube.com/watch?v=ebUrdg2vFNk
## Remediation


https://www.youtube.com/watch?v=FG2DXkPA93g&t=124s
# Your OS is not up to date

## Threat


**Dimension : system integrity / Severity : 3**

Your operating system is not up to date, please proceed to upgrade to get the latest security patches.
## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|iOS 15|Command line|user|latestos_check|

## Rollback


https://www.youtube.com/watch?v=1FcE86kwODQ
## Remediation


https://www.youtube.com/watch?v=1FcE86kwODQ