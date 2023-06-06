
Linux Threat Model (FR)
=======================

Contents
========

* [Edamame Helper inactif](#edamame-helper-inactif)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
* [Permissions du fichier /etc/passwd](#permissions-du-fichier-etcpasswd)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
* [Permissions du fichier /etc/shadow](#permissions-du-fichier-etcshadow)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
* [Permissions du fichier /etc/fstab](#permissions-du-fichier-etcfstab)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
* [Permissions du fichier /etc/group](#permissions-du-fichier-etcgroup)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
* [](#)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
* [](#)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
* [Cron n'est pas restreint à l'utilisateur root](#cron-nest-pas-restreint--lutilisateur-root)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
* [Système non à jour](#systme-non--jour)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
* [](#)
	* [Menace](#menace)
	* [Implémentation](#implmentation)
	* [Retour en arrière](#retour-en-arrire)
	* [Remédiation](#remdiation)
* [Uncomplicated firewall non installé](#uncomplicated-firewall-non-install)
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
|Linux 6|Ligne de commande|admin|ps -ef \| grep edamame_helper \| grep -v grep > /dev/null \|\| echo nohelper|

## Retour en arrière

## Remédiation

# Permissions du fichier /etc/passwd

## Menace


**Dimension : system integrity / Sévérité : 5**

Le fichier `/etc/passwd` dans les systèmes Unix et Linux contient des informations sur les comptes utilisateurs. Les permissions recommandées pour ce fichier sont `644`. Cela signifie que :
- Le propriétaire (généralement `root`) a les permissions de lecture et d'écriture (6).
- Le groupe et les autres utilisateurs ont les permissions de lecture seule (4).
Cette configuration garantit que seul le superutilisateur peut modifier le fichier, préservant ainsi la sécurité du système. Pendant ce temps, les autres utilisateurs et processus peuvent toujours lire les informations dont ils ont besoin à partir du fichier. Cet équilibre entre fonctionnalité et sécurité est la raison pour laquelle les permissions `644` sont considérées comme une bonne pratique pour le fichier `/etc/passwd`.
## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Linux 6|Ligne de commande|system|stat /etc/passwd \| grep '(0644/-rw-r--r--)' \| grep -v grep > /dev/null \|\| echo bad_permissions|

## Retour en arrière
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Linux 6|Ligne de commande|system|chmod 664 /etc/passwd|

## Remédiation

# Permissions du fichier /etc/shadow

## Menace


**Dimension : system integrity / Sévérité : 5**

Le fichier `/etc/shadow` dans les systèmes Unix et Linux stocke les données de mot de passe cryptées pour chaque utilisateur et a des permissions plus strictes que `/etc/passwd`. Cela est dû au fait que `/etc/shadow` contient des données sensibles.
Les permissions recommandées pour le fichier `/etc/shadow` sont `600` :
- `6` (lecture et écriture) pour le propriétaire, qui devrait être l'utilisateur root ou superutilisateur. Cela permet au système de modifier le fichier lorsque les mots de passe sont changés.
- `0` pour le groupe et les autres. Cela signifie qu'aucune permission n'est donnée au groupe ou aux autres, ce qui signifie qu'ils ne peuvent pas lire, écrire ou exécuter le fichier.
## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Linux 6|Ligne de commande|system|stat /etc/shadow \| grep '(0600/-rw-------)' \| grep -v grep > /dev/null \|\| echo bad_permissions|

## Retour en arrière
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Linux 6|Ligne de commande|system|chmod 600 /etc/shadow|

## Remédiation

# Permissions du fichier /etc/fstab

## Menace


**Dimension : system integrity / Sévérité : 5**

Le fichier `/etc/fstab` dans les systèmes Unix et Linux fournit une table des systèmes de fichiers qui doivent être montés automatiquement au démarrage du système. Ce fichier contient des informations importantes telles que les systèmes de fichiers à monter, où les monter et quelles options utiliser.
Compte tenu de son importance, les permissions recommandées pour le fichier `/etc/fstab` sont `644` :
- `6` (lecture et écriture) pour le propriétaire, qui devrait être l'utilisateur root ou superutilisateur. Cela permet au système de modifier le fichier lorsque des systèmes de fichiers sont ajoutés ou supprimés.
- `4` (lecture seule) pour le groupe et les autres. Cela permet aux utilisateurs et aux processus de lire le fichier et de comprendre les systèmes de fichiers du système, mais les empêche d'apporter des modifications potentiellement nuisibles.
Cette configuration garantit que seul l'utilisateur root peut modifier le fichier, protégeant ainsi la configuration du système de fichiers du système. En même temps, elle permet aux autres utilisateurs et processus de lire le fichier, fournissant l'accès nécessaire aux informations sur le système de fichiers.
## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Linux 6|Ligne de commande|system|stat /etc/fstab \| grep '(0644/-rw-r--r--)' \| grep -v grep > /dev/null \|\| echo bad_permissions|

## Retour en arrière
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Linux 6|Ligne de commande|system|chmod 644 /etc/fstab|

## Remédiation

# Permissions du fichier /etc/group

## Menace


**Dimension : system integrity / Sévérité : 5**

Le fichier `/etc/group` dans les systèmes Unix et Linux stocke les informations ou les données des groupes. Il contient une liste de tous les groupes sur le système, ainsi que les utilisateurs associés à chaque groupe.
Compte tenu de son importance, les permissions recommandées pour le fichier `/etc/group` sont `644` :
- `6` (lecture et écriture) pour le propriétaire, qui devrait être l'utilisateur root ou superutilisateur. Cela permet au système d'ajouter ou de supprimer des groupes ou de modifier l'appartenance à un groupe.
- `4` (lecture seule) pour le groupe et les autres. Cela permet aux utilisateurs et aux processus de lire le fichier et de comprendre l'appartenance aux groupes du système, mais les empêche de faire des modifications non autorisées.
Cette configuration garantit que seul l'utilisateur root peut modifier le fichier, protégeant ainsi la configuration des groupes du système. En même temps, elle permet aux autres utilisateurs et processus de lire le fichier, fournissant l'accès nécessaire aux informations sur les groupes.
## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Linux 6|Ligne de commande|system|stat /etc/group \| grep '(0644/-rw-r--r--)' \| grep -v grep > /dev/null \|\| echo bad_permissions|

## Retour en arrière
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Linux 6|Ligne de commande|system|chmod 644 /etc/group|

## Remédiation

# 

## Menace


**Dimension : system integrity / Sévérité : 5**


## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Linux 6|Ligne de commande|system|ls -l /etc/group \| grep 'root root' \| grep -v grep > /dev/null \|\| echo bad_group|

## Retour en arrière
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Linux 6|Ligne de commande|system|chown root /etc/group|

## Remédiation

# 

## Menace


**Dimension : system integrity / Sévérité : 5**


## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Linux 6|Ligne de commande|system|ls -l /etc/shadow \| grep 'root root' \| grep -v grep > /dev/null \|\| echo bad_group|

## Retour en arrière
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Linux 6|Ligne de commande|system|chown root /etc/shadow|

## Remédiation

# Cron n'est pas restreint à l'utilisateur root

## Menace


**Dimension : system integrity / Sévérité : 5**

Cron est un planificateur de tâches basé sur le temps dans les systèmes d'exploitation de type Unix. Les utilisateurs peuvent programmer des tâches (commandes ou scripts) pour qu'elles s'exécutent périodiquement à des heures, des dates ou des intervalles fixes. C'est un outil puissant, mais qui peut également poser des risques de sécurité s'il n'est pas géré correctement. Restreindre les tâches cron à l'utilisateur root est généralement considéré comme une bonne pratique.
## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Linux 6|Ligne de commande|system|cd /etc ; [ -f cron.deny ] && echo bad_config ; grep -v root cron.allow|

## Retour en arrière
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Linux 6|Ligne de commande|system|cd /etc ; [ -f cron.deny ] && mv cron.deny cron.deny.edamame_save ; [ -f cron.allow ] && mv cron.allow cron.allow.edamame_save ; echo root > cron.allow ; chown root cron.allow ; chmod 400 cron.allow|

## Remédiation

# Système non à jour

## Menace


**Dimension : system integrity / Sévérité : 5**

Garder un système Linux (ou tout autre système d'exploitation) à jour est crucial pour plusieurs raisons, en particulier en ce qui concerne la sécurité : les développeurs trouvent et corrigent régulièrement des vulnérabilités de sécurité dans les logiciels. Ces correctifs, appelés patches, sont distribués via des mises à jour. En mettant régulièrement à jour votre système, vous assurez l'application rapide de ces patches, réduisant ainsi les chances d'une attaque réussie.
## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Linux 6|Ligne de commande|system|checkupdates; [ $? -eq 0 ] && echo updates_required|

## Retour en arrière
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Linux 6|Ligne de commande|system|pacman -Syu --noconfirm|

## Remédiation

# 

## Menace


**Dimension : Credentials / Sévérité : 3**


## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Linux 6|Ligne de commande|system|[ $(grep '^PASS_MAX_DAYS' /etc/login.defs \| awk '{print $NF}') -lt 90 ] \|\| echo pass_max_days_too_long|

## Retour en arrière

## Remédiation

# Uncomplicated firewall non installé

## Menace


**Dimension : network / Sévérité : 3**

Un pare-feu est un élément crucial de tout cadre de sécurité réseau. Les pare-feu contrôlent le trafic réseau entrant et sortant en fonction de règles de sécurité prédéterminées. Ils établissent une barrière entre les réseaux internes de confiance et les réseaux externes non fiables. Il peut également bloquer l'accès non autorisé vers ou depuis des réseaux privés, empêchant les intrus d'accéder à des informations sensibles. Uncomplicated firewall fournit une interface en ligne de commande et vise à être simple d'utilisation.
## Implémentation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Linux 6|Ligne de commande|system|pacman -Qi ufw > /dev/null \|\| echo not_found|

## Retour en arrière
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Linux 6|Ligne de commande|system|pacman -S ufw; ufw enable; ufw default deny; ufw allow from 192.168.0.0/24; ufw allow Deluge; ufw limit ssh|

## Remédiation
  

|Testé pour|Action|Elevation|Script|
| :--- | :--- | :--- | :--- |
|Linux 6|Ligne de commande||pacman -R ufw|
