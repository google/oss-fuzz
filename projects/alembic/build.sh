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

mkdir -p $WORK/build_openexr
mkdir -p $WORK/build_alembic

# build openexr for alembic
cd $WORK/build_openexr
OPENEXR_CMAKE_SETTINGS=(
  "-D BUILD_SHARED_LIBS=OFF"         # Build static libraries only
  "-D PYILMBASE_ENABLE=OFF"          # Don't build Python support
  "-D BUILD_TESTING=OFF"             # Or tests
  "-D INSTALL_OPENEXR_EXAMPLES=OFF"  # Or examples
  "-D OPENEXR_LIB_SUFFIX="           # Don't append the version number to library files
  "-D ILMBASE_LIB_SUFFIX="
)
cmake $SRC/openexr ${OPENEXR_CMAKE_SETTINGS[@]}
make -j$(nproc) && make install

# build alembic
cd $WORK/build_alembic
cmake $SRC/alembic -DALEMBIC_SHARED_LIBS=OFF
make -j$(nproc)

INCLUDES=(
  "-I $SRC"
  "-I ${SRC}/alembic/lib"
  "-I ${WORK}/build_alembic/lib"
  "-I /usr/local/include/OpenEXR"
)
LIBS=("-lImath" "-lIex" "-lHalf")

for fuzzer in $(find $SRC -name '*_fuzzer.cc'); do
  fuzzer_basename=$(basename -s .cc $fuzzer)
  $CXX $CXXFLAGS -std=c++11 ${INCLUDES[@]} \
    $fuzzer $WORK/build_alembic/lib/Alembic/libAlembic.a $LIB_FUZZING_ENGINE \
    -o $OUT/$fuzzer_basename ${LIBS[@]}
done
