#!/bin/bash

apt update -qq > /dev/null 2>&1 ||
true &&
apt install xrdp -y > /dev/null 2>&1 &&
systemctl start xrdp &&
systemctl enable xrdp
