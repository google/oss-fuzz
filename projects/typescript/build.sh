#!/bin/bash -eu
# Copyright 2023 Google LLC
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

# Install dependencies.
npm install
npm install --save-dev @jazzer.js/core

# Build Fuzzers.
# Fuzzing TS is a resource hog so we have to adjust the rss limit a bit
compile_javascript_fuzzer TypeScript fuzz_ast -i typescript -- -rss_limit_mb=4096
compile_javascript_fuzzer TypeScript fuzz_compiler -i typescript --sync -- -rss_limit_mb=4096
compile_javascript_fuzzer TypeScript fuzz_scanner -i typescript --sync -- -rss_limit_mb=4096
compile_javascript_fuzzer TypeScript fuzz_json_parser -i typescript --sync -- -rss_limit_mb=4096
compile_javascript_fuzzer TypeScript fuzz_transpile_module -i typescript --sync -- -rss_limit_mb=4096
