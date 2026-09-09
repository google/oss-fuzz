#!/bin/bash -eu
# Copyright 2026 Google LLC
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

cd $SRC/hami-core

F=$SRC/hami-core-fuzz
CUDA_INC=/usr/local/cuda-12.9/targets/x86_64-linux/include
INC="-I$SRC/hami-core/src -I$CUDA_INC -I$F/include"

# Fuzzed parsers live in multiprocess_memory_limit.c; its driver/NVML
# references are satisfied by driver_stubs.c.
$CC $CFLAGS -std=gnu11 $INC \
    -c src/multiprocess/multiprocess_memory_limit.c -o $WORK/memory_limit.o
$CC $CFLAGS -std=gnu11 -I$CUDA_INC -c $F/driver_stubs.c -o $WORK/driver_stubs.o

for target in env_value_fuzzer env_file_fuzzer; do
    $CC $CFLAGS -std=gnu11 $INC -c $F/$target.c -o $WORK/$target.o
    $CXX $CXXFLAGS -o $OUT/$target $WORK/$target.o $WORK/memory_limit.o \
        $WORK/driver_stubs.o -lpthread $LIB_FUZZING_ENGINE
done
