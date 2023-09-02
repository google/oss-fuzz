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

# Remove exceptions
sed -i '/throw TC_EndpointParse_Exception/c\return;' ./util/src/tc_clientsocket.cpp

# Build library
cmake -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON .
make V=1

# Build fuzzer(s)
mv $SRC/tc_endpoint_fuzzer.cpp $SRC/TarsCpp/util/src/
$CXX $CXXFLAGS -I/src/TarsCpp/util/include -c util/src/tc_endpoint_fuzzer.cpp -o tcp_endpoint_fuzzer.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE tcp_endpoint_fuzzer.o -o $OUT/tcp_endpoint_fuzzer ./lib/libtarsutil.a
