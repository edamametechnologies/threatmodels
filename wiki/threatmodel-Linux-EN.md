
Linux Threat Model (EN)
=======================

Contents
========

* [Edamame helper inactive](#edamame-helper-inactive)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [File permissions /etc/passwd](#file-permissions-etcpasswd)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [File permissions /etc/shadow](#file-permissions-etcshadow)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [File permissions /etc/fstab](#file-permissions-etcfstab)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [File permissions /etc/group](#file-permissions-etcgroup)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [](#)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [Permissions checks](#permissions-checks)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [Cron is not restricted to root only](#cron-is-not-restricted-to-root-only)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [Missing system updates](#missing-system-updates)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [Permissions checks](#permissions-checks)
	* [Threat](#threat)
	* [Implementation](#implementation)
	* [Rollback](#rollback)
	* [Remediation](#remediation)
* [Uncomplicated firewall not installed](#uncomplicated-firewall-not-installed)
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
|Linux 6|Command line|admin|ps -ef \| grep edamame_helper \| grep -v grep > /dev/null \|\| echo nohelper|

## Rollback

## Remediation

# File permissions /etc/passwd

## Threat


**Dimension : system integrity / Severity : 5**

The /etc/passwd file in Unix and Linux systems contains user account information. The recommended permissions for this file are 644. This means:
The owner (usually root) has read and write permissions (6).
The group and other users have read-only permissions (4).
This setup ensures that only the superuser can modify the file, preserving system security. Meanwhile, other users and processes can still read the information they need from the file. This balance of functionality and security is why 644 permissions are considered good practice for the /etc/passwd file.
## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Linux 6|Command line|system|stat /etc/passwd \| grep '(0644/-rw-r--r--)' \| grep -v grep > /dev/null \|\| echo bad_permissions|

## Rollback
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Linux 6|Command line|system|chmod 664 /etc/passwd|

## Remediation

# File permissions /etc/shadow

## Threat


**Dimension : system integrity / Severity : 5**

The /etc/shadow file in Unix and Linux systems stores encrypted password data for each user and has stricter permissions than /etc/passwd. This is because /etc/shadow contains sensitive data.
The recommended permissions for the /etc/shadow file are 600:
6 (read and write) for the owner, who should be the root or superuser. This allows the system to modify the file when passwords are changed.
0 for the group and others. This means no permissions are given to the group or others, meaning they cannot read, write, or execute the file.
## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Linux 6|Command line|system|stat /etc/shadow \| grep '(0600/-rw-------)' \| grep -v grep > /dev/null \|\| echo bad_permissions|

## Rollback
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Linux 6|Command line|system|chmod 600 /etc/shadow|

## Remediation

# File permissions /etc/fstab

## Threat


**Dimension : system integrity / Severity : 5**

The `/etc/fstab` file in Unix and Linux systems provides a table of filesystems that should be mounted automatically at system startup. This file contains important information like what filesystems to mount, where to mount them, and what options to use.
Given its significance, the recommended permissions for the `/etc/fstab` file are `644`:
- `6` (read and write) for the owner, which should be the root or superuser. This allows the system to modify the file when filesystems are added or removed.
- `4` (read-only) for the group and others. This allows users and processes to read the file and understand the system's filesystems, but prevents them from making potentially harmful changes.
This setup ensures only the root user can modify the file, protecting the system's filesystem configuration. Meanwhile, it allows other users and processes to read the file, providing necessary access to filesystem information.
## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Linux 6|Command line|system|stat /etc/fstab \| grep '(0644/-rw-r--r--)' \| grep -v grep > /dev/null \|\| echo bad_permissions|

## Rollback
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Linux 6|Command line|system|chmod 644 /etc/fstab|

## Remediation

# File permissions /etc/group

## Threat


**Dimension : system integrity / Severity : 5**

The `/etc/group` file in Unix and Linux systems stores group information or data. It contains a list of all the groups on the system, along with each group's associated users.
Given its importance, the recommended permissions for the `/etc/group` file are `644`:
- `6` (read and write) for the owner, which should be the root or superuser. This allows the system to add or remove groups or modify group membership.
- `4` (read-only) for the group and others. This allows users and processes to read the file and understand the system's group memberships, but prevents them from making unauthorized changes.
This setup ensures only the root user can modify the file, protecting the system's group configuration. Meanwhile, it allows other users and processes to read the file, providing necessary access to group information.
## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Linux 6|Command line|system|stat /etc/group \| grep '(0644/-rw-r--r--)' \| grep -v grep > /dev/null \|\| echo bad_permissions|

## Rollback
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Linux 6|Command line|system|chmod 644 /etc/group|

## Remediation

# 

## Threat


**Dimension : system integrity / Severity : 5**


## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Linux 6|Command line|system|ls -l /etc/group \| grep 'root root' \| grep -v grep > /dev/null \|\| echo bad_group|

## Rollback
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Linux 6|Command line|system|chown root /etc/group|

## Remediation

# Permissions checks

## Threat


**Dimension : system integrity / Severity : 5**


## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Linux 6|Command line|system|ls -l /etc/shadow \| grep 'root root' \| grep -v grep > /dev/null \|\| echo bad_group|

## Rollback
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Linux 6|Command line|system|chown root /etc/shadow|

## Remediation

# Cron is not restricted to root only

## Threat


**Dimension : system integrity / Severity : 5**

Cron is a time-based job scheduler in Unix-like operating systems. Users can schedule jobs (commands or scripts) to run periodically at fixed times, dates, or intervals. It's a powerful tool, but can also pose security risks if not managed properly. Restricting cron jobs to the root user is generally considered good practice.
## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Linux 6|Command line|system|cd /etc ; [ -f cron.deny ] && echo bad_config ; grep -v root cron.allow|

## Rollback
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Linux 6|Command line|system|cd /etc ; [ -f cron.deny ] && mv cron.deny cron.deny.edamame_save ; [ -f cron.allow ] && mv cron.allow cron.allow.edamame_save ; echo root > cron.allow ; chown root cron.allow ; chmod 400 cron.allow|

## Remediation

# Missing system updates

## Threat


**Dimension : system integrity / Severity : 5**

Keeping a Linux system (or any operating system) up-to-date is crucial for several reasons, particularly when it comes to security: developers regularly find and fix security vulnerabilities in software. These fixes, known as patches, are distributed via updates. By regularly updating your system, you ensure these patches are applied promptly, reducing the chance of a successful attack.
## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Linux 6|Command line|system|checkupdates; [ $? -eq 0 ] && echo updates_required|

## Rollback
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Linux 6|Command line|system|pacman -Syu --noconfirm|

## Remediation

# Permissions checks

## Threat


**Dimension : Credentials / Severity : 3**


## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Linux 6|Command line|system|[ $(grep '^PASS_MAX_DAYS' /etc/login.defs \| awk '{print $NF}') -lt 90 ] \|\| echo pass_max_days_too_long|

## Rollback

## Remediation

# Uncomplicated firewall not installed

## Threat


**Dimension : network / Severity : 3**

A firewall is a crucial part of any network security framework. Firewalls control the incoming and outgoing network traffic based on predetermined security rules. They establish a barrier between trusted internal networks and untrusted external networks. It can also block unauthorized access to or from private networks, preventing intruders from accessing sensitive information. Uncomplicated firewall provides a command line interface and aims to be uncomplicated and easy to use.
## Implementation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Linux 6|Command line|system|pacman -Qi ufw > /dev/null \|\| echo not_found|

## Rollback
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Linux 6|Command line|system|pacman -S ufw; ufw enable; ufw default deny; ufw allow from 192.168.0.0/24; ufw allow Deluge; ufw limit ssh|

## Remediation
  

|Tested for|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Linux 6|Command line||pacman -R ufw|
