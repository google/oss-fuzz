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

CMAKE_SETTINGS=(
  "-D BUILD_SHARED_LIBS=OFF"         # Build static libraries only
  "-D PYILMBASE_ENABLE=OFF"          # Don't build Python support
  "-D BUILD_TESTING=OFF"             # Or tests
  "-D OPENEXR_BUILD_UTILS=OFF"       # Or utilities
  "-D INSTALL_OPENEXR_EXAMPLES=OFF"  # Or examples
  "-D OPENEXR_LIB_SUFFIX="           # Don't append the version number to library files
  "-D ILMBASE_LIB_SUFFIX="
)
cmake $SRC/openexr ${CMAKE_SETTINGS[@]}
make -j$(nproc)

INCLUDES=(
  "-I $SRC/openexr/OpenEXR/IlmImf"
  "-I $SRC/openexr/IlmBase/Imath"
  "-I $SRC/openexr/IlmBase/Iex"
  "-I $SRC/openexr/IlmBase/Half"
  "-I $WORK/OpenEXR/config"
  "-I $WORK/IlmBase/config"
)

LIBS=(
  "$WORK/OpenEXR/IlmImf/libIlmImf.a"
  "$WORK/IlmBase/Iex/libIex.a"
  "$WORK/IlmBase/Half/libHalf.a"
  "$WORK/IlmBase/IlmThread/libIlmThread.a"
  "$WORK/IlmBase/Imath/libImath.a"
)

for fuzzer in $SRC/*_fuzzer.cc; do
  fuzzer_basename=$(basename -s .cc $fuzzer)
  $CXX $CXXFLAGS -std=c++11 -pthread ${INCLUDES[@]} $fuzzer $LIB_FUZZING_ENGINE ${LIBS[@]} -lz \
    -o $OUT/$fuzzer_basename
done
