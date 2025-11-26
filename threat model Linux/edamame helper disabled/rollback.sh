#!/bin/sh
# Metric: edamame helper disabled

if command -v apk >/dev/null 2>&1; then
    apk del edamame_helper
else
apt remove edamame_helper
fi
