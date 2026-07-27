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

# Compile the fuzzer using our shims to bypass D-Bus/systemd dependencies
$CXX $CXXFLAGS -std=c++23 \
    -I$SRC/pldm_shims \
    -I$SRC/pldm \
    -I/usr/local/include \
    $SRC/pldm/fw-update/package_parser.cpp \
    $SRC/pldm_package_parser_fuzzer.cc \
    -o $OUT/pldm_package_parser_fuzzer \
    $LIB_FUZZING_ENGINE -lpldm
