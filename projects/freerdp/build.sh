#!/bin/bash -eu
# Copyright 2023 Google LLC
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

# Avoid compilation issue due to some undefined references. They are defined in
# libc++ and used by Centipede so -lc++ needs to come after centipede's lib.
if [[ $FUZZING_ENGINE == centipede ]]
then
    sed -i \
        '/$ENV{LIB_FUZZING_ENGINE}/a \ \ \ \ \ \ \ \ -lc++' \
        cmake/ConfigOptions.cmake
fi

case $SANITIZER in
  address) SANITIZERS_ARGS="-DWITH_SANITIZE_ADDRESS=ON" ;;
  memory) SANITIZERS_ARGS="-DWITH_SANITIZE_MEMORY=ON" ;;
  *) SANITIZERS_ARGS="" ;;
esac

: ${LD:="${CXX}"}
: ${LDFLAGS:="${CXXFLAGS}"}  # to make sure we link with sanitizer runtime

cmake_args=(
    # Specific to FreeRDP.
    -DWITH_SAMPLE=OFF
    -DWITH_SERVER=ON
    -DWITH_PROXY=OFF
    -DWITH_SHADOW=OFF
    -DWITH_CLIENT=OFF
    -DWITH_ALSA=OFF
    -DWITH_X11=OFF
    -DWITH_LIBSYSTEMD=OFF
    -DWITH_FUSE=OFF
    -DWITH_AAD=OFF
    -DWITH_FFMPEG=OFF
    -DWITH_SWSCALE=OFF

    # clang-15 segfaults on linking binaries when LTO is enabled,
    # see https://github.com/google/oss-fuzz/pull/10448#issuecomment-1578160436
    -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=OFF

    $SANITIZERS_ARGS

    -DCMAKE_BUILD_TYPE=Debug
    -DBUILD_SHARED_LIBS=OFF
    -DOSS_FUZZ=ON
    -DBUILD_FUZZERS=ON
    -DBUILD_TESTING=ON

    # C compiler
    -DCMAKE_C_COMPILER="${CC}"
    -DCMAKE_C_FLAGS="${CFLAGS}"

    # C++ compiler
    -DCMAKE_CXX_COMPILER="${CXX}"
    -DCMAKE_CXX_FLAGS="${CXXFLAGS}"

    # Linker
    -DCMAKE_LINKER="${LD}"
    -DCMAKE_EXE_LINKER_FLAGS="${LDFLAGS}"
    -DCMAKE_MODULE_LINKER_FLAGS="${LDFLAGS}"
    -DCMAKE_SHARED_LINKER_FLAGS="${LDFLAGS}"
)

# Build the project and fuzzers.
rm -rf build
cmake "${cmake_args[@]}" -S . -B build -G Ninja
cmake --build build --parallel --target fuzzers

for f in $(find build/Testing/ -name 'TestFuzz*' -type f);
do
    cp $f $OUT/
done
