#!/bin/bash

ls -l /etc/shadow | grep -q 'root shadow' ||
echo bad_group
