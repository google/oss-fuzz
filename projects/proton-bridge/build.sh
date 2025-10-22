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

cd "$SRC"
cd go-118-fuzz-build
go build .
mv go-118-fuzz-build /root/go/bin/
cd "$SRC"/proton-bridge

mkdir pkg/fuzzing
printf "package fuzzing\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > pkg/fuzzing/register.go
go mod edit -replace github.com/AdamKorcz/go-118-fuzz-build="$SRC"/go-118-fuzz-build
go mod tidy

export PROJ="github.com/ProtonMail/proton-bridge/v3"
compile_native_go_fuzzer   $PROJ/internal/legacy/credentials     FuzzUnmarshal               fuzz_unmarshal   
compile_native_go_fuzzer   $PROJ/pkg/message/parser              FuzzNewParser               fuzz_new_parser
compile_native_go_fuzzer   $PROJ/pkg/message                     FuzzReadHeaderBody          fuzz_read_header_body
compile_native_go_fuzzer   $PROJ/pkg/mime                        FuzzDecodeHeader            fuzz_decode_header
compile_native_go_fuzzer   $PROJ/pkg/mime                        FuzzDecodeCharset           fuzz_decode_charset
