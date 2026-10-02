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

# Install Prettier's own dependencies. Prettier ships its sources runnable
# as-is from the repo (package.json "main" -> "./src/index.cjs"), so no build
# step is required for the fuzz targets to require it.
npm install --ignore-scripts

# Install Jazzer.js. Prettier's `format` API is asynchronous since v3, so the
# fuzz targets are written as async functions and we do NOT pass --sync.
# Pinned to 2.1.0 because the 4.0.0 prebuilt native addon requires GLIBC_2.32,
# which is not available in the current base-builder-javascript image.
npm install --save-dev @jazzer.js/core@2.1.0

# Build fuzzers.
compile_javascript_fuzzer prettier fuzz_targets/fuzz_format_js.js
compile_javascript_fuzzer prettier fuzz_targets/fuzz_format_ts.js
compile_javascript_fuzzer prettier fuzz_targets/fuzz_format_css.js
compile_javascript_fuzzer prettier fuzz_targets/fuzz_format_json.js
compile_javascript_fuzzer prettier fuzz_targets/fuzz_format_md.js
