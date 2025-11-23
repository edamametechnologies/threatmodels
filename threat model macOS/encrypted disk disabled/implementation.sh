#!/bin/bash

system_profiler SPHardwareDataType | grep -q 'Virtual' ||
fdesetup isactive | grep false
