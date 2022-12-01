#!/bin/sh

set -e

rm -f barebones.hdd
dd if=/dev/zero bs=1M count=0 seek=64 of=barebones.hdd
parted -s barebones.hdd mklabel gpt
parted -s barebones.hdd mkpart ESP fat32 2048s 100%
parted -s barebones.hdd set 1 esp on
sudo losetup -Pf --show barebones.hdd >loopback_dev
sudo mkfs.fat -F 32 `cat loopback_dev`p1
sync
sudo losetup -d `cat loopback_dev`
rm -rf loopback_dev
