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
    -I$SRC/stdplus/include \
    -I$SRC/hothd_shims \
    -I$SRC/hothd \
    -I$SRC/hothd/google3 \
    $SRC/stdplus/src/exception.cpp \
    $SRC/stdplus/src/print.cpp \
    $SRC/stdplus/src/raw.cpp \
    $SRC/hothd/payload_update.cpp \
    $SRC/hothd_payload_fuzzer.cc \
    -o $OUT/hothd_payload_fuzzer \
    $LIB_FUZZING_ENGINE
