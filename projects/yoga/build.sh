#!/bin/bash -eu
# Copyright 2024 Google LLC
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
# NOTE: We intentionally do NOT build with -D CMAKE_BUILD_TYPE="Release".
# Yoga's cmake/project-defaults.cmake adds "-ffunction-sections -fdata-sections"
# and "-Wl,--gc-sections" only for the Release configuration. Under the AFL++
# engine these strip the linker sections holding AFL's persistent-mode /
# fork-server initialisation, which makes the fuzzer hang on its first input
# (afl-fuzz reports "All test cases time out") and breaks `check_build`.
# Omitting the Release type keeps OSS-Fuzz's own -O1 from $CFLAGS/$CXXFLAGS and
# leaves the AFL instrumentation intact.
cmake -B build -S . -D BUILD_FUZZ_TESTS=ON -Dcxx_no_rtti=OFF -G Ninja
cmake --build build --target fuzz_layout

cp ./build/fuzz/fuzz_layout $OUT/
