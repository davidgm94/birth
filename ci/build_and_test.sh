#!/bin/sh

set -x
set -e

zig env
zig build test_all -Dci --verbose
