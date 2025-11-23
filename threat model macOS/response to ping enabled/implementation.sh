#!/bin/bash

/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode | grep -E "disabled|is off"
