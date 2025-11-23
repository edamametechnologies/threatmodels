#!/bin/bash

grep -q "BEGIN RESTRICT_ZSH_NONADMINS" /etc/zshrc ||
echo CLI not restricted
