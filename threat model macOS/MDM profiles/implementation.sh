#!/bin/bash

profiles -P | grep profileIdentifier | grep -v digital_health_restrictions | grep -v dateandtime
