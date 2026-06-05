#!/bin/bash -eu
# Copyright 2022 Google LLC
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
export CFLAGS="$CFLAGS -DPJMEDIA_HAS_VIDEO=1"
export CXXFLAGS="$CFLAGS"
export LDFLAGS="$CFLAGS"

# Temporary workaround for pjproject#4988: the Opus block in fuzz-audio.c has an
# unterminated /* ... comment right before the stereo-config block, which the
# preprocessor swallows along with the block's variable declarations and opening
# brace, breaking the build. Insert the missing */ after the comment's last line.
# Remove this once the upstream comment is closed.
sed -i '/registered "opus\/48000\/2" ID)\./a\     */' tests/fuzz/fuzz-audio.c

./configure \
--disable-ffmpeg --disable-ssl \
--disable-speex-aec --disable-g7221-codec \
--disable-resample --disable-libwebrtc --disable-libyuv

# Force static linking of libvpx and libopus so the fuzzers do not depend on
# .so files that are absent from the OSS-Fuzz runner image. libvpx-dev and
# libopus-dev both ship .a archives in /usr/lib/x86_64-linux-gnu/.
sed -i 's|-lvpx|/usr/lib/x86_64-linux-gnu/libvpx.a|g' build.mak
sed -i 's|-lopus|/usr/lib/x86_64-linux-gnu/libopus.a|g' build.mak

make dep
make -j$(nproc) --ignore-errors
make fuzz

pushd tests/fuzz/
FuzzBins=$(find . -name "*.c")

for File in $FuzzBins; do
    FuzzBin=$(basename $File .c)
    cp $FuzzBin $OUT/$FuzzBin
    echo -e "[libfuzzer]\nmax_len=16384" > $OUT/${FuzzBin}.options
done
popd

# Copy all seed corpus and dictionaries to $OUT
cp tests/fuzz/seed/* $OUT/
