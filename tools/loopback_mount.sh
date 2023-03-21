#!/bin/sh
# $1 = Loopback device
# $2 = Mount directory
set -e
#echo "Mounting loopback device $1 in directory $2..."
sudo mount `cat $1`p1 $2
