#!/bin/bash

launchctl print-disabled system | grep com.apple.AEServer | grep -E 'enabled|false'
