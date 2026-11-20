#!/bin/bash -eux
# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

OSS_FUZZ_BUILD_DIR="./build-oss-fuzz/"
cd $OSS_FUZZ_BUILD_DIR

# Prepare third party libraries directory
DEST_DIR=$OUT
mkdir -p "$DEST_DIR/lib/"

# Build fuzzing harnesses and libs
make "-j$(nproc)" qemu-fuzz-i386 V=1

# Install data files
make install DESTDIR=$DEST_DIR/qemu-bundle
rm -rf $DEST_DIR/qemu-bundle/opt/qemu-oss-fuzz/bin
rm -rf $DEST_DIR/qemu-bundle/opt/qemu-oss-fuzz/libexec


# Copy over the libraries needed by the fuzzer, mirroring what
# scripts/oss-fuzz/build.sh does:
# https://github.com/qemu/qemu/blob/master/scripts/oss-fuzz/build.sh
# We derive the list with ldd rather than hardcoding sonames, which drift
# between base images (e.g. libffi.so.7 on ubuntu-20-04 vs libffi.so.8 on
# ubuntu-24-04), and avoid calling `configure`, which needs network access
# and is much slower.
for i in $(ldd ./qemu-fuzz-i386 | cut -f3 -d' '); do
    cp "$i" "$DEST_DIR/lib/"
done

export ASAN_OPTIONS=detect_leaks=0
targets=$(./qemu-fuzz-i386 | grep generic-fuzz | awk '$1 ~ /\*/  {print $2}')
base_copy="$DEST_DIR/qemu-fuzz-i386-target-$(echo "$targets" | head -n 1)"

cp "./qemu-fuzz-i386" "$base_copy"

# Generate the actual fuzzing harnesses
for target in $(echo "$targets" | tail -n +2);
do
    # Skip generic harness.
    if [[ $target == "generic-fuzz-"* ]]; then
        ln  $base_copy \
            "$DEST_DIR/qemu-fuzz-i386-target-$target"
    fi
done
