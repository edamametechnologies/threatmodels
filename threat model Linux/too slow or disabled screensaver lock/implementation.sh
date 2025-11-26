#!/bin/sh

if command -v gsettings >/dev/null 2>&1; then
    LANG=C gsettings get org.gnome.desktop.screensaver lock-enabled | grep -q 'true' || echo screensaver_lock_disabled
else
    # If gsettings is missing, we can't verify, but existing logic implies disabled if check fails
echo screensaver_lock_disabled
fi
