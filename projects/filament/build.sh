#!/bin/bash -eu
# Copyright 2021 Google LLC
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


# Build Filament
cd $SRC/filament
git checkout v1.9.23

mkdir build-dir
cd build-dir
cmake -DFILAMENT_ENABLE_JAVA=OFF \
	-DFILAMENT_SKIP_SAMPLES=ON \
	-DVIDEO_X11=OFF \
	-DFILAMENT_OSS_FUZZ=ON \
	..
make

# Build fuzzers
cd $SRC/filament
$CXX $CXXFLAGS \
        -I./filament/include \
        -I./build-dir/filament \
        -I./filament/src \
        -I./filament/backend/include \
        -I./libs/math/include \
        -I./libs/utils/include \
        -I./third_party/robin-map \
        -I./libs/filaflat/include \
        -I./libs/filabridge/include \
        -std=c++17 \
        -fstrict-aliasing \
        -stdlib=libc++ -fPIC \
        -o material_parser_fuzzer.o \
        -c $SRC/material_parser_fuzzer.cpp


$CXX $CXXFLAGS $LIB_FUZZING_ENGINE material_parser_fuzzer.o \
        -o $OUT/material_parser_fuzzer -std=c++17 \
        -fPIC  -Wl,--gc-sections \
        ./build-dir/filament/libfilament.a \
        ./build-dir/libs/filaflat/libfilaflat.a \
        ./build-dir/libs/filabridge/libfilabridge.a \
        ./build-dir/libs/utils/libutils.a  \
        ./build-dir/third_party/smol-v/tnt/libsmol-v.a

