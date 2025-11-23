#!/bin/bash

dscl . -read /Users/root Password | grep '\*\*'
