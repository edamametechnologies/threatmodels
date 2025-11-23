#!/bin/bash

apt update -qq > /dev/null 2>&1 ||
true &&
apt install samba -y > /dev/null 2>&1 &&
systemctl start smbd &&
systemctl enable smbd &&
apt install nfs-kernel-server -y > /dev/null 2>&1 &&
systemctl start nfs-kernel-server &&
systemctl enable nfs-kernel-server
