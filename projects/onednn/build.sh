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

sed -i 's/FATAL_ERROR/WARNING/g' ./cmake/OpenMP.cmake
mkdir build
cd build
cmake -DDNNL_LIBRARY_TYPE=STATIC -DDNNL_BUILD_TESTS=OFF -DDNNL_BUILD_EXAMPLES=OFF ..
make -j2

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE $SRC/fuzz_json.cpp \
	-I/src/oneDNN/include -I/src/oneDNN/build/include \
	-I/src/oneDNN/examples -I/src/oneDNN/src/../include \
	-I/src/oneDNN/src/graph/utils/ \
	-I/src/oneDNN/src/ \
	-DDNNL_X64=1 -D__STDC_CONSTANT_MACROS -D__STDC_LIMIT_MACROS \
	-o $OUT/fuzz_json \
	./src/libdnnl.a
