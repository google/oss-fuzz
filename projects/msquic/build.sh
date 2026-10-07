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

# Temporary workaround for clang-18
export CFLAGS="$CFLAGS     -Wno-error=invalid-unevaluated-string"
export CXXFLAGS="$CXXFLAGS -Wno-error=invalid-unevaluated-string"

pwsh ./scripts/build.ps1 -Static -DisableTest -DisablePerf -DisableLogs -Parallel 1

BUILDFILENAME=$(find . -name 'msquic-config.cmake')
BUILDDIR=$(dirname $BUILDFILENAME)
LIBMSQUICDIR=$(cmake -LAH $BUILDDIR/CMakeCache.txt | grep QUIC_OUTPUT_DIR | cut -d'=' -f 2)
QUICTLSLIB=$(cmake -LAH $BUILDDIR/CMakeCache.txt | grep  QUIC_TLS_LIB | cut -d'=' -f 2)

cd $SRC/msquic/src/fuzzing

$CXX $CXXFLAGS -DCX_PLATFORM_LINUX -DQUIC_TEST_APIS \
    -I/src/msquic/src/test \
    -I/src/msquic/src/inc \
    -I/src/msquic/src/generated/common \
    -I/src/msquic/src/generated/linux \
    -I/src/msquic/build/linux/x64_$QUICTLSLIB/_deps/opensslquic-build/$QUICTLSLIB/include \
    -isystem /src/msquic/submodules/googletest/googletest/include \
    -isystem /src/msquic/submodules/googletest/googletest \
    -c fuzz.cc -o fuzz.o


$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz.o -o $OUT/fuzz \
    $LIBMSQUICDIR/libmsquic.a

cd $SRC

$CXX $CXXFLAGS -DCX_PLATFORM_LINUX -DQUIC_TEST_APIS -DFUZZING -DQUIC_BUILD_STATIC \
    -I/src/msquic/src/test \
    -I/src/msquic/src/inc \
    -I/src/msquic/src/generated/common \
    -I/src/msquic/src/generated/linux \
    -I/src/msquic/build/linux/x64_$QUICTLSLIB/_deps/opensslquic-build/$QUICTLSLIB/include \
    -isystem /src/msquic/submodules/googletest/googletest/include \
    -isystem /src/msquic/submodules/googletest/googletest \
    -c ./msquic/src/tools/spin/spinquic.cpp -o spinquic.o

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE spinquic.o -o $OUT/spinquic \
    $LIBMSQUICDIR/libmsquic.a
