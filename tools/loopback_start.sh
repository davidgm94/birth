#!/bin/sh
# $1 = Disk image
# $2 = Loopback device
set -e
#echo "Starting loopback device $2 with image $1..."
sudo losetup -Pf --show $1 > $2
