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

git submodule update --init --recursive
mkdir build && cd build
cmake -DBUILD_SHARED_LIBS=OFF \
	  -DWANT_ICU=OFF \
	  -DWANT_OPENSSL=OFF \
	  -DWANT_ZLIB=OFF \
	  -DWANT_IPV6=OFF ..
make -j$(nproc)

$CXX $CXXFLAGS -DGTEST_HAS_POSIX_RE=0 \
	-I/src/znc/include -I/src/znc/build/include \
	-fPIE -include znc/zncconfig.h -std=c++11 \
	-c $SRC/msg_parse_fuzzer.cpp -o msg_parse_fuzzer.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
	msg_parse_fuzzer.o -o $OUT/msg_parse_fuzzer \
	/src/znc/build/src/libznc.a 
