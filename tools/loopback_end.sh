#!/bin/sh
# $1 = Loopback device
set -e
echo "Deleting loopback device $1..."
sudo losetup -d `cat $1`
