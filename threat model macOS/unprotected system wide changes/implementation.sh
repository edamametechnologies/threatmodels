#!/bin/bash

security authorizationdb read system.preferences 2> /dev/null | grep -A1 shared | grep true
