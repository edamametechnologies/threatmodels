#!/bin/sh

ecryptfs-setup-private 2>&1 | grep -q 'wrapped-passphrase file already exists' ||
echo encryption_inactive
