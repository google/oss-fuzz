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

# Install rollup (from npm, ships prebuilt native bindings for linux-x64-gnu)
# together with Jazzer.js, in the fuzz workspace prepared by the Dockerfile.
npm install
npm install --save-dev @jazzer.js/core

# Build fuzzers. The "-i rollup" flag tells Jazzer.js to instrument the
# rollup package so coverage is tracked across rollup's JavaScript runtime.
compile_javascript_fuzzer rollup-fuzz fuzz_parse_ast -i rollup --sync
compile_javascript_fuzzer rollup-fuzz fuzz_log_filter -i rollup --sync
compile_javascript_fuzzer rollup-fuzz fuzz_bundle -i rollup
