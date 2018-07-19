#!/bin/bash -eu
# Copyright 2018 Google Inc.
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

# build project
mkdir -p build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX="$WORK" \
      -DBUILD_SHARED_LIBS=OFF \
      -DBUILD_CLAR=OFF \
      -DUSE_HTTPS=OFF \
      -DUSE_SSH=OFF \
      -DUSE_BUNDLED_ZLIB=ON \

make -j$(nproc)
make install

$CXX $CXXFLAGS -std=c++11 -I"$WORK/include" \
    /src/download_refs_fuzzer.cc -o $OUT/download_refs_fuzzer \
    -lFuzzingEngine "$WORK/lib/libgit2.a"

zip -j "$OUT/download_refs_fuzzer_seed_corpus.zip" $SRC/corpora/download_refs/*
