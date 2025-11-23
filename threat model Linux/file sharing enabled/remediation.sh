#!/bin/bash

systemctl stop smbd &&
systemctl disable smbd;
systemctl stop nfs-kernel-server &&
systemctl disable nfs-kernel-server
