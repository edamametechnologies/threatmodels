#!/bin/bash

system_profiler SPHardwareDataType 2>/dev/null | grep -v 'hw\.cpufamily' | grep -q 'Virtual' ||
fdesetup isactive | grep false
