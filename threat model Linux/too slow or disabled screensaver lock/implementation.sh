#!/bin/bash

LANG=C gsettings get org.gnome.desktop.screensaver lock-enabled | grep -q 'true' ||
echo screensaver_lock_disabled
