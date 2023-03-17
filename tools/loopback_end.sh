#!/bin/sh
# $1 = Loopback device
set -e
sudo losetup -d `cat $1`
