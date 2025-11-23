#!/bin/bash

apt update -qq > /dev/null 2>&1 ||
true &&
apt install ufw -y > /dev/null 2>&1 &&
ufw enable
