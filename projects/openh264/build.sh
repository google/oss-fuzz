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

# prepare corpus
zip -q0r ${OUT}/decoder_fuzzer_seed_corpus.zip ./res/

# build 
make -j$(nproc) USE_ASM=No BUILDTYPE=Debug libraries
$CXX $CXXFLAGS -o $OUT/decoder_fuzzer -I./codec/api/svc -I./codec/console/common/inc -I./codec/common/inc -L. -lFuzzingEngine $SRC/decoder_fuzzer.cpp libopenh264.a
