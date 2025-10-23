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


# Copy over the librarise needed by the fuzzer.
# These are the libraries copied from https://github.com/qemu/qemu/blob/88b1716a407459c8189473e4667653cb8e4c3df7/scripts/oss-fuzz/build.sh#L78
# We do it this way, to avoid calling `configure`, which is called twice in the
# build.sh.
# Configure poses problems because it relies on network activity and also
# performance is a lot better without configure.
cp /lib/x86_64-linux-gnu/libstdc++.so.6 /out/lib/
cp /lib/x86_64-linux-gnu/libpixman-1.so.0 /out/lib/
cp /lib/x86_64-linux-gnu/libz.so.1 /out/lib/
cp /lib/x86_64-linux-gnu/libfdt.so.1 /out/lib/
cp /lib/x86_64-linux-gnu/libgio-2.0.so.0 /out/lib/
cp /lib/x86_64-linux-gnu/libgobject-2.0.so.0 /out/lib/
cp /lib/x86_64-linux-gnu/libglib-2.0.so.0 /out/lib/
cp /lib/x86_64-linux-gnu/libslirp.so.0 /out/lib/
cp /lib/x86_64-linux-gnu/libutil.so.1 /out/lib/
cp /lib/x86_64-linux-gnu/libgmodule-2.0.so.0 /out/lib/
cp /lib/x86_64-linux-gnu/libm.so.6 /out/lib/
cp /lib/x86_64-linux-gnu/libpthread.so.0 /out/lib/
cp /lib/x86_64-linux-gnu/librt.so.1 /out/lib/
cp /lib/x86_64-linux-gnu/libdl.so.2 /out/lib/
cp /lib/x86_64-linux-gnu/libresolv.so.2 /out/lib/
cp /lib/x86_64-linux-gnu/libgcc_s.so.1 /out/lib/
cp /lib/x86_64-linux-gnu/libc.so.6 /out/lib/
cp /lib/x86_64-linux-gnu/libffi.so.7 /out/lib/

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
