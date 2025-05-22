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

# Use fuzzer-file paths instead of kernel paths
sed -i 's/"\/proc\/cpuinfo"/"\/tmp\/libfuzzer.config"/g' src/x86/linux/cpuinfo.c
sed -i 's/"\/sys\/devices\/system\/cpu\/kernel_max"/"\/tmp\/libfuzzer.config"/g' src/linux/processors.c
mkdir build
cd build
cmake ..
make


$CC $CFLAGS -c $SRC/fuzz_cpuinfo.c -o fuzz_cpuinfo.o \
    -I/src/cpuinfo/src -I/src/cpuinfo/include
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_cpuinfo.o -o $OUT/fuzz_cpuinfo \
    ./libcpuinfo.a
