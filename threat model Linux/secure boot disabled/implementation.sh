#!/bin/bash
 and reports the finding using the commands below.

LANG=C mokutil --sb-state | grep -q 'SecureBoot enabled' ||
echo secure_boot_disabled
