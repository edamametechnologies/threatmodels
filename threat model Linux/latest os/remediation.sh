#!/bin/bash

apt update -qq > /dev/null 2>&1 ||
true &&
apt upgrade -y
