#!/bin/bash -eu
#
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

git apply --ignore-space-change --ignore-whitespace $SRC/fuzz-patch.diff

mkdir -p build
cd build

sed -i 's/fput/\/\/fput/g' $SRC/vulkan-loader/loader/log.c

cmake -DUPDATE_DEPS=ON -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)

ar rcs $OUT/libvulkan.a $SRC/vulkan-loader/build/loader/CMakeFiles/vulkan.dir/*.o

$CC $CFLAGS -I$SRC/vulkan-loader/loader \
    -I$SRC/vulkan-loader/loader/generated \
    -I$SRC/vulkan-headers/include \
    -I$SRC/ \
    -DENABLE_FILE_CALLBACK \
    -c $SRC/instance_create_advanced_fuzzer.c -o instance_create_advanced_fuzzer.o

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE instance_create_advanced_fuzzer.o \
    -o $OUT/instance_create_advanced_fuzzer -lpthread $OUT/libvulkan.a
zip -q $OUT/instance_create_advanced_fuzzer_seed_corpus.zip $SRC/vulkan-loader/tests/corpus/*
cp $SRC/vulkan-keywords.dict $OUT/instance_create_advanced_fuzzer.dict

$CC $CXXFLAGS -I$SRC/vulkan-loader/loader \
    -I$SRC/vulkan-loader/loader/generated \
    -I$SRC/vulkan-headers/include \
    -DSPLIT_INPUT \
    -c $SRC/instance_enumerate_fuzzer.c -o instance_enumerate_fuzzer_split_input.o

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE instance_enumerate_fuzzer_split_input.o \
    -o $OUT/instance_enumerate_fuzzer_split_input -lpthread $OUT/libvulkan.a
cp $SRC/vulkan-keywords.dict $OUT/instance_enumerate_fuzzer_split_input.dict

for fuzzer in instance_create_fuzzer json_load_fuzzer settings_fuzzer instance_enumerate_fuzzer; do
    #fuzz_basename=$(basename -s .c $fuzzers)
    $CC $CXXFLAGS -I$SRC/vulkan-loader/loader \
        -I$SRC/vulkan-loader/loader/generated \
        -I$SRC/vulkan-headers/include \
        -c $SRC/$fuzzer.c -o $fuzzer.o

    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE $fuzzer.o \
        -o $OUT/$fuzzer -lpthread $OUT/libvulkan.a

    zip -q $OUT/${fuzzer}_seed_corpus.zip $SRC/vulkan-loader/tests/corpus/*
    cp $SRC/vulkan-keywords.dict $OUT/$fuzzer.dict
done
