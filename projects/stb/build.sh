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
# Run the OSS-Fuzz script in the project
$SRC/stb/tests/ossfuzz.sh

# Additional fuzzers
$CXX $CXXFLAGS -std=c++11 -I. -DSTB_IMAGE_IMPLEMENTATION  \
    $SRC/stb/tests/stbi_gif_read_fuzzer.c \
    -o $OUT/stb_gif_read_fuzzer $LIB_FUZZING_ENGINE

$CXX $CXXFLAGS -std=c++11 -I. -DSTB_IMAGE_IMPLEMENTATION  \
    $SRC/stb/tests/stbi_bmp_read_fuzzer.c \
    -o $OUT/stb_bmp_read_fuzzer $LIB_FUZZING_ENGINE

$CXX $CXXFLAGS -std=c++11 -I. -DSTB_IMAGE_IMPLEMENTATION  \
    $SRC/stb/tests/stbi_jpeg_read_fuzzer.c \
    -o $OUT/stb_jpeg_read_fuzzer $LIB_FUZZING_ENGINE

$CXX $CXXFLAGS -std=c++11 -I. -DSTB_IMAGE_IMPLEMENTATION  \
    $SRC/stb/tests/stbi_pic_read_fuzzer.c \
    -o $OUT/stb_pic_read_fuzzer $LIB_FUZZING_ENGINE

$CXX $CXXFLAGS -std=c++11 -I. -DSTB_IMAGE_IMPLEMENTATION  \
    $SRC/stb/tests/stbi_psd_read_fuzzer.c \
    -o $OUT/stb_psd_read_fuzzer $LIB_FUZZING_ENGINE

$CXX $CXXFLAGS -std=c++11 -I. -DSTB_IMAGE_IMPLEMENTATION  \
    $SRC/stb/tests/stbi_extended_read_fuzzer.c \
    -o $OUT/stb_extended_read_fuzzer $LIB_FUZZING_ENGINE
