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

$CXX $CXXFLAGS -std=c++23 \
    -I$SRC/estoraged_shims \
    -I$SRC/estoraged/include \
    -I$SRC/estoraged/src \
    $SRC/estoraged/src/erase/pattern.cpp \
    $SRC/estoraged/src/erase/zero.cpp \
    $SRC/estoraged/src/erase/cryptoErase.cpp \
    $SRC/estoraged/src/util.cpp \
    $SRC/estoraged_fuzzer.cc \
    -o $OUT/estoraged_fuzzer \
    $LIB_FUZZING_ENGINE
