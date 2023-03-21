#!/bin/sh
# $1 Loopback device
set -e
sudo mkfs.fat -F 32 `cat $1`p1 1>2
