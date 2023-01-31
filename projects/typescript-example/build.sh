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

# Install Jazzer.js before building the code since use the fuzzed data provider
# in the fuzz test
npm install --save-dev @jazzer.js/core

# Compile TypeScript code.
npm run build

# Build Fuzzers.
compile_javascript_fuzzer example dist/fuzz_explore_me.js --sync
