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
#
################################################################################

# oss-fuzz/projects/gemini-cli/build.sh
#
# Build JS fuzzers for gemini-cli using OSS-Fuzz JS helpers.
# This script is invoked by OSS-Fuzz infra.

# go to project dir
cd $SRC/projects/gemini-cli || true

# Ensure upstream TypeScript packages are built (OSS-Fuzz places upstream at /src/gemini-cli)
if [ -d /src/gemini-cli ]; then
  pushd /src/gemini-cli || true
  if [ -f package.json ]; then
    npm ci
    # run the upstream build if it exists (doesn't fail the build if no script)
    npm run build || true
  fi
  popd || true
fi

# ensure node + npm are present (OSS-Fuzz base-builder-javascript provides them)
# set up fuzzer deps
cd fuzzers
if [ -f package.json ]; then
  npm ci
fi

# compile JS fuzzers (name of exported function must match the second arg)
# compile_js_fuzzer <entry-file> <exported-func-name>
# the OSS-Fuzz build environment provides compile_js_fuzzer helper
compile_js_fuzzer fuzz_config_parser.js FuzzConfigParser
compile_js_fuzzer fuzz_cli_parser.js FuzzCLIParser
compile_js_fuzzer fuzz_mcp_request.js FuzzMCPRequest
compile_js_fuzzer fuzz_mcp_response.js FuzzMCPResponse
compile_js_fuzzer fuzz_oauth_token_request.js FuzzOAuthTokenRequest
compile_js_fuzzer fuzz_oauth_token_response.js FuzzOAuthTokenResponse
