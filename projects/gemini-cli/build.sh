#!/bin/bash -eu
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

cd $SRC/gemini-cli
npm ci

# Compile JavaScript fuzzers
compile_javascript_fuzzer . fuzzers/fuzz_json_decoder.js --sync
compile_javascript_fuzzer . fuzzers/fuzz_http_header.js --sync
compile_javascript_fuzzer . fuzzers/fuzz_proxy_security.js --sync
compile_javascript_fuzzer . fuzzers/fuzz_mcp_decoder.js --sync
compile_javascript_fuzzer . fuzzers/fuzz_url.js --sync

# Optimize node_modules for performance
npm prune --omit=dev
npm install @jazzer.js/core

# Create optimized archive for runtime
tar -czf node_modules.tar.gz node_modules
cp node_modules.tar.gz $OUT/
