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

cd "$SRC"/go-118-fuzz-build
go build
rm "$GOPATH"/bin/go-118-fuzz-build
mv go-118-fuzz-build "$GOPATH"/bin/

cd "$SRC"/gateway

set -o nounset
set -o pipefail
set -o errexit
set -x
printf "package envoygateway\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > register.go
go mod edit -replace github.com/AdamKorcz/go-118-fuzz-build="$SRC"/go-118-fuzz-build
go mod tidy

# compile native-format fuzzers
compile_native_go_fuzzer github.com/envoyproxy/gateway/test/fuzz FuzzGatewayAPIToXDS FuzzGatewayAPIToXDS

# add seed corpus
zip -j "$OUT"/FuzzGatewayAPIToXDS_seed_corpus.zip "$SRC"/gateway/test/fuzz/testdata/FuzzGatewayAPIToXDS/*
