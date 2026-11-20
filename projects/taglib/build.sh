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

# Build taglib as a static library with the fuzzing compilers and flags.
cd $SRC/taglib
rm -rf build
cmake -S . -B build \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_TESTING=OFF \
    -DBUILD_BINDINGS=OFF \
    -DBUILD_EXAMPLES=OFF \
    -DBUILD_SHARED_LIBS=OFF \
    -DENABLE_CCACHE=OFF \
    -DVISIBILITY_HIDDEN=OFF
cmake --build build -j$(nproc)

# Compile the fuzz target maintained in taglib's own tests/fuzzing directory.
$CXX $CXXFLAGS -std=c++17 \
    -I $SRC/taglib/taglib \
    -I $SRC/taglib/taglib/toolkit \
    -I $SRC/taglib/build \
    $SRC/taglib/tests/fuzzing/taglib_fileref_fuzzer.cpp \
    $SRC/taglib/build/taglib/libtag.a -lz \
    $LIB_FUZZING_ENGINE \
    -o $OUT/taglib_fileref_fuzzer

# Format dictionary, also maintained upstream.
cp $SRC/taglib/tests/fuzzing/taglib.dict $OUT/taglib_fileref_fuzzer.dict

# Seed corpus built from taglib's own test data (LGPL/MPL, same project).
zip -j -q $OUT/taglib_fileref_fuzzer_seed_corpus.zip $SRC/taglib/tests/data/*

# Round-trip fuzzer
TAGLIB_RND_INCS="-I $SRC/taglib/taglib -I $SRC/taglib/taglib/toolkit -I $SRC/taglib/build"
for d in ape asf dsdiff dsf flac it matroska mod mp4 mpc mpeg ogg riff s3m shorten trueaudio wavpack xm; do
  TAGLIB_RND_INCS="$TAGLIB_RND_INCS -I $SRC/taglib/taglib/$d"
done
for d in mpeg/id3v2 ogg/opus ogg/speex ogg/vorbis ogg/flac riff/aiff riff/wav matroska/ebml; do
  TAGLIB_RND_INCS="$TAGLIB_RND_INCS -I $SRC/taglib/taglib/$d"
done
$CXX $CXXFLAGS -std=c++17 $TAGLIB_RND_INCS \
    $SRC/taglib/tests/fuzzing/taglib_roundtrip_fuzzer.cpp \
    $SRC/taglib/build/taglib/libtag.a -lz \
    $LIB_FUZZING_ENGINE \
    -o $OUT/taglib_roundtrip_fuzzer

# Seed corpus for taglib
zip -j -q $OUT/taglib_roundtrip_fuzzer_seed_corpus.zip $SRC/taglib/tests/data/*
cp $SRC/taglib/tests/fuzzing/taglib_roundtrip.dict $OUT/taglib_roundtrip_fuzzer.dict

python3 $SRC/taglib/tests/fuzzing/generate_frame_seeds.py $OUT/generated_seeds
zip -j -q $OUT/taglib_roundtrip_fuzzer_seed_corpus.zip $OUT/generated_seeds/*
rm -rf $OUT/generated_seeds
