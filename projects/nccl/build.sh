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

# CUDA does not support clang versions above 10.0. This should not affect the
# target of the fuzzers, however, during build we still need to allow it to
# compile with the OSS-Fuzz clang version.
sed -i 's/-std=c++11 --expt-extended-lambda/-allow-unsupported-compiler -std=c++11 --expt-extended-lambda/g' ./makefiles/common.mk

make clean
make -j3 src.build

$CXX $LIB_FUZZING_ENGINE $CXXFLAGS $SRC/fuzz_xml.cpp -o $OUT/fuzz_xml \
    -I./src/graph/ -I./src/include -I./build/include/ \
    -I/usr/local/cuda-11.0/targets/x86_64-linux/include/ \
    ./build/lib/libnccl_static.a \
    /usr/local/cuda-11.0/targets/x86_64-linux/lib/libcudart.so

cp /usr/local/cuda-11.0/targets/x86_64-linux/lib/libcudart.so.11.0 /out/
cp /usr/local/cuda-11.0/targets/x86_64-linux/lib/libcudart.so /out/
patchelf --set-rpath '$ORIGIN/' /out/fuzz_xml
