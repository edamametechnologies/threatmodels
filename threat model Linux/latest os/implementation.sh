#!/bin/bash

LANG=C apt update -qq > /dev/null 2>&1 ||
true &&
apt list --upgradeable 2>/dev/null | grep -q 'upgradable' &&
echo os_outdated
