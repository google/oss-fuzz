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
  "-D BUILD_TESTING=OFF"             # Or tests
  "-D OPENEXR_INSTALL_EXAMPLES=OFF"  # Or examples
  "-D OPENEXR_LIB_SUFFIX="           # Don't append the version number to library files
)
cmake $SRC/openexr ${CMAKE_SETTINGS[@]}
make -j$(nproc)

INCLUDES=(
  "-I $SRC"
  "-I $SRC/openexr/src/lib/OpenEXRCore"
  "-I $SRC/openexr/src/lib/OpenEXR"
  "-I $SRC/openexr/src/lib/OpenEXRUtil"
  "-I $WORK/cmake"
)

LIBS=(
  "$WORK/src/lib/OpenEXRUtil/libOpenEXRUtil.a"
  "$WORK/src/lib/OpenEXR/libOpenEXR.a"
  "$WORK/src/lib/OpenEXRCore/libOpenEXRCore.a"
  "$WORK/src/lib/IlmThread/libIlmThread.a"
  "$WORK/src/lib/Iex/libIex.a"
  "$WORK/_deps/imath-build/src/Imath/libImath*.a"
)

for fuzzer in $SRC/openexr/src/test/OpenEXRFuzzTest/oss-fuzz/*_fuzzer.cc; do
  fuzzer_basename=$(basename -s .cc $fuzzer)
  $CXX $CXXFLAGS -std=c++11 -pthread ${INCLUDES[@]} $fuzzer $LIB_FUZZING_ENGINE ${LIBS[@]} -lz \
    -o $OUT/$fuzzer_basename
done
