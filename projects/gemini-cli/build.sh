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

cd $SRC/gemini-cli
go mod download || true

# Build fuzzers
if [ -d "gofuzz/fuzz" ]; then
    compile_go_fuzzer ./gofuzz/fuzz FuzzConfigParser fuzz_config_parser
fi

if [ -d "gofuzz/internal/cli" ]; then
    compile_go_fuzzer ./gofuzz/internal/cli FuzzCLIParser fuzz_cli_parser
fi

if [ -d "gofuzz/internal/mcp" ]; then
    compile_go_fuzzer ./gofuzz/internal/mcp FuzzMCPDecoder fuzz_mcp_decoder
fi

if [ -d "gofuzz/internal/oauth" ]; then
    compile_go_fuzzer ./gofuzz/internal/oauth FuzzOAuthTokenResponse fuzz_oauth_token_response
    compile_go_fuzzer ./gofuzz/internal/oauth FuzzOAuthTokenRequest fuzz_oauth_token_request
fi

# Copy seed corpora
if [ -d "seeds" ]; then
    for dir in seeds/*; do
        if [ -d "$dir" ]; then
            fuzzer_name=$(basename "$dir")
            zip -rj "$OUT/fuzz_${fuzzer_name}_seed_corpus.zip" "$dir"
        fi
    done
fi

find . -name "*.dict" -exec cp {} $OUT/ \;
