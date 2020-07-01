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

cd $WORK/
cmake $SRC/openexr \
  -DPYILMBASE_ENABLE=OFF \
  -DBUILD_TESTING=OFF \
  -DBUILD_SHARED_LIBS=OFF
make -j$(nproc)

OPENEXR_INCLUDES=(
  "-I $SRC/openexr/OpenEXR/IlmImf"
  "-I $SRC/openexr/IlmBase/Imath"
  "-I $SRC/openexr/IlmBase/Iex"
  "-I $SRC/openexr/IlmBase/Half"
  "-I $WORK/OpenEXR/config"
  "-I $WORK/IlmBase/config"
)

OPENEXR_LIBS=(
  "/work/OpenEXR/IlmImf/libIlmImf-2_5.a"
  "/work/IlmBase/Iex/libIex-2_5.a"
  "/work/IlmBase/Half/libHalf-2_5.a"
  "/work/IlmBase/IlmThread/libIlmThread-2_5.a"
  "/work/IlmBase/Imath/libImath-2_5.a"
)

for fuzzer in $SRC/*_fuzzer.cc; do
  fuzzer_basename=$(basename -s .cc $fuzzer)
  $CXX $CXXFLAGS -std=c++11 -pthread \
    ${OPENEXR_INCLUDES[@]} \
    $fuzzer \
    $LIB_FUZZING_ENGINE \
    ${OPENEXR_LIBS[@]} \
    -lz \
    -o $OUT/$fuzzer_basename
done
