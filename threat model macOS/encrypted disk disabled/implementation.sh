#!/bin/bash

system_profiler SPHardwareDataType 2>/dev/null | grep -q 'Virtual' ||
fdesetup isactive | grep false
