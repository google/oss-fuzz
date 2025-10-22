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

# Disable network tests
sed -i '/add_subdirectory(networking_tests)/d' ./tests/CMakeLists.txt
# remove some compiler flags for the tests which have conflict with OSS-Fuzz's flags
sed -i '/target_compile_options(glz_test_common INTERFACE -fno-exceptions -fno-rtti)/d' ./tests/CMakeLists.txt
mkdir build
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release -j$(nproc)

fuzzing/ossfuzz.sh
