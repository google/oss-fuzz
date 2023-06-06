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

mkdir build
cd build
cmake -DXNNPACK_BUILD_BENCHMARKS=OFF -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON -DXNNPACK_BUILD_TESTS=OFF ../
make V=1 -j8
cd ../

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE ../fuzz_model.cc \
    -DFXDIV_USE_INLINE_ASSEMBLY=0 -DPTHREADPOOL_NO_DEPRECATED_API=1 \
    -DXNN_ENABLE_ARM_BF16=1 -DXNN_ENABLE_ARM_DOTPROD=1 \
    -DXNN_ENABLE_ARM_FP16_SCALAR=1 -DXNN_ENABLE_ARM_FP16_VECTOR=1 \
    -DXNN_ENABLE_ASSEMBLY=1 -DXNN_ENABLE_DWCONV_MULTIPASS=0 \
    -DXNN_ENABLE_GEMM_M_SPECIALIZATION=1 -DXNN_ENABLE_JIT=0 \
    -DXNN_ENABLE_MEMOPT=1 -DXNN_ENABLE_RISCV_VECTOR=1 -DXNN_ENABLE_SPARSE=1 \
    -I/src/xnnpack/src -I/src/xnnpack/build/pthreadpool-source/include \
    -I/src/xnnpack/build/FXdiv-source/include -I/src/xnnpack/include/ \
    -I/src/xnnpack/build/FP16-source/include ./build/libXNNPACK.a \
    ./build/pthreadpool/libpthreadpool.a ./build/cpuinfo/libcpuinfo.a \
    -o $OUT/fuzz_model
