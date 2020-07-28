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

mkdir $WORK/build_openexr
mkdir $WORK/build_alembic

# build openexr for alembic
cd $WORK/build_openexr
OPENEXR_CMAKE_SETTINGS=(
  "-D BUILD_SHARED_LIBS=OFF"         # Build static libraries only
  "-D PYILMBASE_ENABLE=OFF"          # Don't build Python support
  "-D BUILD_TESTING=OFF"             # Or tests
  "-D INSTALL_OPENEXR_EXAMPLES=OFF"  # Or examples
)
cmake $SRC/openexr ${OPENEXR_CMAKE_SETTINGS[@]}
make -j$(nproc) && make install

# build alembic
cd $WORK/build_alembic
ALEMBIC_CMAKE_SETTINGS=(
  "-D ALEMBIC_SHARED_LIBS=OFF"                        # Build static libs only
  "-D ALEMBIC_ILMBASE_LINK_STATIC=ON"                 # Link OpenEXR static libs
  "-D ILMBASE_INCLUDE_DIR=/usr/local/include/OpenEXR" # Set include directory
  "-D ILMBASE_ROOT=/usr/local/lib/"                   # Set library directory
)
cmake $SRC/alembic ${ALEMBIC_CMAKE_SETTINGS[@]}
make -j$(nproc) && make install

INCLUDES=(
  "-I $SRC/alembic"
  "-I $WORK/build_alembic"
  "-I /usr/local/include/OpenEXR"
)

LIBS=(
  "/usr/local/lib/libIlmImf*.a"
  "/usr/local/lib/libIex*.a"
  "/usr/local/lib/libHalf*.a"
  "/usr/local/lib/libIlmThread*.a"
  "/usr/local/lib/libImath*.a"
  "/usr/local/lib/libIexMath*.a"
  "$WORK/build_alembic/lib/Alembic/libAlembic.a"
)

for fuzzer in $(find $SRC -name '*_fuzzer.cc'); do
  fuzzer_basename=$(basename -s .cc $fuzzer)
  $CXX $CXXFLAGS -std=c++11 ${INCLUDES[@]} \
      $fuzzer ${LIBS[@]} $LIB_FUZZING_ENGINE \
      -o $OUT/$fuzzer_basename
done
