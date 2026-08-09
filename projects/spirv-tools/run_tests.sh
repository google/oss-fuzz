#!/bin/bash -eu
#
# Copyright 2025 Google LLC
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

# Skip copyrights check
# Skip shared symbol check since the fuzzing build only build static tools
# Run unit testing
ctest --test-dir build -j$(nproc) -E "spirv-tools-copyrights|spirv-tools-symbol-exports-SPIRV-Tools-shared"
