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

./configure \
--disable-ffmpeg --disable-ssl \
--disable-speex-aec --disable-speex-codec \
--disable-g7221-codec --disable-gsm-codec --disable-ilbc-codec \
--disable-resample --disable-libsrtp --disable-libwebrtc --disable-libyuv

make dep
make -j$(nproc) --ignore-errors
make fuzz

pushd tests/fuzz/
FuzzBins=$(find . -name "*.c")

for File in $FuzzBins; do
    FuzzBin=$(basename $File .c)
    cp $FuzzBin $OUT/$FuzzBin
done
popd

pushd tests/fuzz/seed/
FuzzSeed=$(find . -name "*.zip")

for Seed in $FuzzSeed; do
    cp $Seed $OUT/$Seed
done
popd
