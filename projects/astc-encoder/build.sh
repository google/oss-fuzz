# !/bin/bash -eu
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

# build project
patch Makefile Makefile.patch
make -j$(nproc) BUILD=debug
ar -qc libastc.a  *.o

# build fuzzers
for fuzzer in $SRC/*_fuzzer.cc; do
  $CXX $CXXFLAGS \
      -DASTCENC_SSE=0 -DASTCENC_AVX=0 -DASTCENC_POPCNT=0 -DASTCENC_VECALIGN=16 \
      -I. -std=c++14 $fuzzer $LIB_FUZZING_ENGINE $SRC/astc-encoder/Source/libastc.a \
      -o $OUT/$(basename -s .cc $fuzzer)
done
