#!/bin/sh
set -ex

sudo losetup -Pf --show barebones.hdd >loopback_dev
mkdir -p img_mount
sudo mount `cat loopback_dev`p1 img_mount
sudo cp -v $1 img_mount$2
sync
sudo umount img_mount
sudo losetup -d `cat loopback_dev`
rm -rf loopback_dev img_mount
