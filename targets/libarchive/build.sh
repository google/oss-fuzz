#!/bin/bash -eu
# Copyright 2016 Google Inc.
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

# build the target.
./build/autogen.sh
./configure
make -j$(nproc) all

# build your fuzzer(s)
$CXX $CXXFLAGS -Ilibarchive \
    $SRC/libarchive_fuzzer.cc -o $OUT/libarchive_fuzzer \
    -lfuzzer .libs/libarchive.a $FUZZER_LDFLAGS \
    -lbz2 -llzo2 -llzma -lxml2 -lz -lcrypto -llz4
