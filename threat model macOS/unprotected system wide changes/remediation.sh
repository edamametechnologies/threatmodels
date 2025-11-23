#!/bin/bash

security authorizationdb read system.preferences > /tmp/system.preferences.plist;
/usr/libexec/PlistBuddy -c "Set :shared false" /tmp/system.preferences.plist;
security authorizationdb write system.preferences < /tmp/system.preferences.plist
