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
svn export https://github.com/mozillasecurity/fuzzdata.git/trunk/samples/h264 corpus/
mv ./res/*.264 ./corpus/
zip -j0r ${OUT}/decoder_fuzzer_seed_corpus.zip ./corpus/

# build 
if [[ $CXXFLAGS = *sanitize=memory* ]]; then
  ASM_BUILD=No
else
  ASM_BUILD=Yes
fi
make -j$(nproc) ARCH=$ARCHITECTURE USE_ASM=$ASM_BUILD BUILDTYPE=Debug libraries
$CXX $CXXFLAGS -o $OUT/decoder_fuzzer -I./codec/api/wels -I./codec/console/common/inc -I./codec/common/inc -L. $LIB_FUZZING_ENGINE $SRC/decoder_fuzzer.cpp libopenh264.a
