#!/bin/bash -eu
# Copyright 2022 Google Inc.
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

pwsh ./scripts/build.ps1 -Static -DisableTest -DisablePerf -DisableLogs -Parallel 1

cd $SRC/msquic/src/fuzzing

$CXX $CXXFLAGS -DCX_PLATFORM_LINUX -DQUIC_TEST_APIS \
    -I/src/msquic/src/test \
    -I/src/msquic/src/inc \
    -I/src/msquic/src/generated/common \
    -I/src/msquic/src/generated/linux \
    -I/src/msquic/build/linux/x64_openssl/_deps/opensslquic-build/openssl/include \
    -isystem /src/msquic/submodules/googletest/googletest/include \
    -isystem /src/msquic/submodules/googletest/googletest \
    -c fuzz.cc -o fuzz.o

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz.o -o $OUT/fuzz \
    /src/msquic/artifacts/bin/linux/x64_Debug_openssl/libmsquic.a

cd $SRC

$CXX $CXXFLAGS -DCX_PLATFORM_LINUX -DQUIC_TEST_APIS -DFUZZING -DQUIC_BUILD_STATIC \
    -I/src/msquic/src/test \
    -I/src/msquic/src/inc \
    -I/src/msquic/src/generated/common \
    -I/src/msquic/src/generated/linux \
    -I/src/msquic/build/linux/x64_openssl/_deps/opensslquic-build/openssl/include \
    -isystem /src/msquic/submodules/googletest/googletest/include \
    -isystem /src/msquic/submodules/googletest/googletest \
    -c ./msquic/src/tools/spin/spinquic.cpp -o spinquic.o

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE spinquic.o -o $OUT/spinquic \
    /src/msquic/artifacts/bin/linux/x64_Debug_openssl/libmsquic.a
