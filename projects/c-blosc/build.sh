#!/bin/bash -eu
# Copyright 2019 Google Inc.
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

# Build with fuzzer and unit test (Turn on shared build for unit testing only)
# Shared library of local zstd requires x64 architecture, thus disable it
# in i386 architecture
if [ "$ARCHITECTURE" = "i386" ]; then
    cmake . -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
            -DBUILD_FUZZERS=ON -DBUILD_TESTS=ON -DBUILD_BENCHMARKS=OFF \
            -DBUILD_STATIC=ON -DBUILD_SHARED=ON -DDEACTIVATE_ZSTD=ON
else
    cmake . -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
            -DBUILD_FUZZERS=ON -DBUILD_TESTS=ON -DBUILD_BENCHMARKS=OFF \
            -DBUILD_STATIC=ON -DBUILD_SHARED=ON
fi
make clean
make -j$(nproc)

# Package seed corpus
zip -j $OUT/decompress_fuzzer_seed_corpus.zip compat/*.cdata

# getitem_fuzzer consumes real-versioned frames as seeds; its harness reads
# start/nitems from 4 trailing bytes, so append a valid tail (start=0,
# nitems=2048) to each frame instead of shipping the frames bare
mkdir -p /tmp/getitem-seeds
for f in compat/*.cdata; do
    t=/tmp/getitem-seeds/$(basename "$f").tail
    cp "$f" "$t"
    printf '\x00\x00\x08\x00' >> "$t"
done
zip -j $OUT/getitem_fuzzer_seed_corpus.zip /tmp/getitem-seeds/*
cp -v $SRC/getitem_fuzzer.options $OUT/
# Copy the fuzzer executables, zip-ed corpora, and dictionary files to $OUT
find . -name '*_fuzzer' -exec cp -v '{}' $OUT ';'
find . -name '*_fuzzer.dict' -exec cp -v '{}' $OUT ';'
find . -name '*_fuzzer_seed_corpus.zip' -exec cp -v '{}' $OUT ';'
