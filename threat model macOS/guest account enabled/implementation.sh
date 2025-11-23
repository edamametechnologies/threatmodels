#!/bin/bash

sysadminctl -guestAccount status 2>&1 | grep enabled
