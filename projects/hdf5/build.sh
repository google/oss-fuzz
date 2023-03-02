#!/bin/bash -eu
# Copyright 2023 Google LLC.
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

export LDFLAGS="${CFLAGS}"
export CMAKE_C_FLAGS="${CC} ${CFLAGS}"
export CMAKE_CXX_FLAGS="${CXX} ${CXXFLAGS}"

mkdir build-dir
cd build-dir
cmake -G "Unix Makefiles" \
    -DCMAKE_BUILD_TYPE:STRING=Release \
    -DBUILD_SHARED_LIBS:BOOL=OFF \
    -DBUILD_TESTING:BOOL=OFF \
    -DCMAKE_VERBOSE_MAKEFILES:BOOL=ON \
    -DHDF5_BUILD_EXAMPLES:BOOL=OFF \
    -DHDF5_BUILD_TOOLS:BOOL=OFF \
    -DHDF5_ENABLE_SANITIZERS:BOOL=ON \
    -DHDF5_ENABLE_Z_LIB_SUPPORT:BOOL=ON \
    ..

# Make the build verbose for easy logging inspection
cmake --build . --verbose --config Release -j$(nproc)
cd $SRC/hdf5

$CC $CFLAGS  -std=c99 -c \
  -I/src/hdf5/src -I/src/hdf5/build-dir/src -I./src/H5FDsubfiling/ \
  $SRC/h5_read_fuzzer.c
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE h5_read_fuzzer.o ./build-dir/bin/libhdf5.a -lz -o $OUT/h5_read_fuzzer


$CC $CFLAGS  -std=c99 -c \
  -I/src/hdf5/src -I/src/hdf5/build-dir/src -I./src/H5FDsubfiling/ \
  $SRC/h5_extended_fuzzer.c
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE h5_extended_fuzzer.o ./build-dir/bin/libhdf5.a -lz -o $OUT/h5_extended_fuzzer

zip -j $OUT/h5_extended_fuzzer_seed_corpus.zip $SRC/hdf5/test/*.h5
cp $SRC/*.options $OUT/
