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

# Build libhevc
build_dir=$WORK/build
rm -rf ${build_dir}
mkdir -p ${build_dir}
pushd ${build_dir}

cmake $SRC/libhevc
make -j$(nproc)
popd

# build fuzzers
$CXX $CXXFLAGS -std=c++11 \
-I$SRC/libhevc \
-I$SRC/libhevc/common \
-I$SRC/libhevc/decoder \
-I${build_dir} \
-Wl,--start-group \
$LIB_FUZZING_ENGINE \
$SRC/libhevc/fuzzer/hevc_dec_fuzzer.cpp -o $OUT/hevc_dec_fuzzer \
${build_dir}/libhevcdec.a \
-Wl,--end-group

cp $SRC/libhevc/fuzzer/hevc_dec_fuzzer.dict $OUT/hevc_dec_fuzzer.dict
