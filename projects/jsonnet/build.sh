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

mkdir jsonnet/build
pushd jsonnet/build
cmake -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" \
  -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CXXFLAGS" -DBUILD_TESTS=OFF ..
make -j$(nproc)
popd

INSTALL_DIR="$SRC/jsonnet"

for fuzzer in convert_jsonnet_fuzzer_regular \
 convert_jsonnet_fuzzer_stream \
 convert_jsonnet_fuzzer_multi; do
  $CXX $CXXFLAGS -I${INSTALL_DIR}/include $LIB_FUZZING_ENGINE \
    $fuzzer.cc -o $OUT/$fuzzer \
    ${INSTALL_DIR}/build/libjsonnet.a \
    ${INSTALL_DIR}/build/libmd5.a \
    ${INSTALL_DIR}/build/libryml.a
done
