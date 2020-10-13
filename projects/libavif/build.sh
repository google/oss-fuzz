#!/bin/bash -eu
# Copyright 2020 Google Inc.
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

# build dav1d
cd ext && bash dav1d.cmd && cd ..

# build libavif
mkdir build
cd build
cmake -G Ninja -DBUILD_SHARED_LIBS=0 -DAVIF_CODEC_DAV1D=1 -DAVIF_LOCAL_DAV1D=1 ..
ninja

# build fuzzer
$CXX $CXXFLAGS -std=c++11 -I../include \
    ../tests/oss-fuzz/avif_decode_fuzzer.cc -o $OUT/avif_decode_fuzzer \
    $LIB_FUZZING_ENGINE libavif.a ../ext/dav1d/build/src/libdav1d.a

# copy seed corpus
cp $SRC/avif_decode_seed_corpus.zip $OUT/

# show contents of $OUT/ for sanity checking
find $OUT/
