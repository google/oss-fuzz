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

# Install project dependencies. ESLint manages its own dev tooling via npm,
# but only the runtime dependencies are required to invoke the public API
# from a fuzz target, so skip optional/scripted prepare steps.
npm install --ignore-scripts --no-audit --no-fund

# Install Jazzer.js so the fuzz targets can use FuzzedDataProvider and the
# compile_javascript_fuzzer wrapper script can drive them. Pin to 2.1.0
# because the prebuilt native fuzzer binary in 4.x requires GLIBC 2.32, which
# is newer than what the OSS-Fuzz base-runner image (Ubuntu 20.04) provides.
npm install --save-dev --no-audit --no-fund @jazzer.js/core@2.1.0

# Build Fuzzers.
compile_javascript_fuzzer eslint fuzz_linter.js --sync
compile_javascript_fuzzer eslint fuzz_verify_and_fix.js --sync
compile_javascript_fuzzer eslint fuzz_source_code.js --sync
