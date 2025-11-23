#!/bin/bash

defaults read /Library/Preferences/com.apple.commerce.plist AutoUpdate 2>&1 | grep -v 1
