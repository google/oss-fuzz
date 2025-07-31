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

cd $SRC/go-118-fuzz-build
go build .
mv go-118-fuzz-build /root/go/bin/

cd $SRC/cometbft
printf "package tests\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > test/fuzz/tests/register.go
go mod edit -replace github.com/AdamKorcz/go-118-fuzz-build=$SRC/go-118-fuzz-build
go mod tidy

export FUZZ_ROOT="github.com/cometbft/cometbft/v2"

build_go_fuzzer() {
	local function="$1"
	local fuzzer="$2"

	go run github.com/orijtech/otils/corpus2ossfuzz@latest -o "$OUT"/"$fuzzer"_seed_corpus.zip -corpus test/fuzz/tests/testdata/fuzz/"$function"
	compile_native_go_fuzzer "$FUZZ_ROOT"/test/fuzz/tests "$function" "$fuzzer"
}

build_go_fuzzer FuzzP2PSecretConnection fuzz_p2p_secretconnection
build_go_fuzzer FuzzMempool fuzz_mempool
build_go_fuzzer FuzzRPCJSONRPCServer fuzz_rpc_jsonrpc_server
