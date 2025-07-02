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
mkdir -p build
cd build

sed -i 's/fput/\/\/fput/g' $SRC/vulkan-loader/loader/log.c

cmake -DUPDATE_DEPS=ON -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)

ar rcs $OUT/libvulkan.a $SRC/vulkan-loader/build/loader/CMakeFiles/vulkan.dir/*.o

for fuzzers in $(find $SRC -name '*_fuzzer.c'); do
    fuzz_basename=$(basename -s .c $fuzzers)
    $CC $CXXFLAGS -I$SRC/vulkan-loader/loader \
        -I$SRC/vulkan-loader/loader/generated \
        -I$SRC/vulkan-headers/include \
        -c $fuzzers -o $fuzz_basename.o
   
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE $fuzz_basename.o \
        -o $OUT/$fuzz_basename -lpthread $OUT/libvulkan.a

    zip -q $OUT/${fuzz_basename}_seed_corpus.zip $SRC/vulkan-loader/tests/corpus/*
    cp $SRC/vulkan-keywords.dict $OUT/$fuzz_basename.dict
done

$CC $CXXFLAGS -I$SRC/vulkan-loader/loader \
    -I$SRC/vulkan-loader/loader/generated \
    -I$SRC/vulkan-headers/include \
    -DSPLIT_INPUT \
    -c $SRC/instance_enumerate_fuzzer.c -o instance_enumerate_fuzzer_split_input.o

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE instance_enumerate_fuzzer_split_input.o \
    -o $OUT/instance_enumerate_fuzzer_split_input -lpthread $OUT/libvulkan.a
cp $SRC/vulkan-keywords.dict $OUT/instance_enumerate_fuzzer_split_input.dict
