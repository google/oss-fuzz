#!/bin/bash -eu
# Copyright 2026 Google LLC
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

# Build static libvgmstream.a with all optional codec backends disabled.
# The parser/demuxer code in src/meta/* is reachable without any of them
# and is the surface we want to fuzz first.

cd $SRC/vgmstream

mkdir -p build_oss_fuzz
cd build_oss_fuzz

cmake -S .. -B . \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_STATIC=ON \
    -DBUILD_CLI=OFF \
    -DBUILD_V123=OFF \
    -DBUILD_AUDACIOUS=OFF \
    -DBUILD_FB2K=OFF \
    -DBUILD_WINAMP=OFF \
    -DBUILD_XMPLAY=OFF \
    -DUSE_MPEG=OFF \
    -DUSE_VORBIS=OFF \
    -DUSE_FFMPEG=OFF \
    -DUSE_G7221=OFF \
    -DUSE_G719=OFF \
    -DUSE_ATRAC9=OFF \
    -DUSE_CELT=OFF \
    -DUSE_SPEEX=OFF \
    -DCMAKE_C_COMPILER="$CC" \
    -DCMAKE_CXX_COMPILER="$CXX" \
    -DCMAKE_C_FLAGS="$CFLAGS" \
    -DCMAKE_CXX_FLAGS="$CXXFLAGS"

make -j$(nproc) libvgmstream

# ----------------------------------------------------------------------------
# Build the fuzzer harness and link against libvgmstream.a
# ----------------------------------------------------------------------------
LIBVGM="$SRC/vgmstream/build_oss_fuzz/src/libvgmstream.a"

$CC $CFLAGS \
    -I$SRC/vgmstream/src \
    -c $SRC/vgmstream_fuzz_bnk.c \
    -o $WORK/vgmstream_fuzz_bnk.o

$CXX $CXXFLAGS \
    $WORK/vgmstream_fuzz_bnk.o \
    "$LIBVGM" \
    $LIB_FUZZING_ENGINE \
    -lm \
    -o $OUT/vgmstream_fuzz_bnk

# ----------------------------------------------------------------------------
# Dictionary
# ----------------------------------------------------------------------------
cp $SRC/vgmstream_fuzz_bnk.dict $OUT/vgmstream_fuzz_bnk.dict

# ----------------------------------------------------------------------------
# Seed corpus — generated at build time so the OSS-Fuzz repo stays small
# and the seeds always match the harness's expected layout.
# ----------------------------------------------------------------------------
mkdir -p $WORK/vgmstream_fuzz_bnk_seeds
python3 $SRC/vgmstream_fuzz_bnk_seedgen.py $WORK/vgmstream_fuzz_bnk_seeds
(cd $WORK/vgmstream_fuzz_bnk_seeds && zip -q -r $OUT/vgmstream_fuzz_bnk_seed_corpus.zip .)
