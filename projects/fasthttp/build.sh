#!/bin/bash -eu
# Copyright 2020 Google Inc.
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

cd $SRC/fasthttp
printf "package fasthttp\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > register.go
go mod edit -replace github.com/AdamKorcz/go-118-fuzz-build="$SRC"/go-118-fuzz-build
go mod tidy

# breaks the coverage build
rm fs_fs_test.go
compile_native_go_fuzzer github.com/valyala/fasthttp FuzzCookieParse fuzzCookieParse
compile_native_go_fuzzer github.com/valyala/fasthttp FuzzVisitHeaderParams fuzzVisitHeaderParams
compile_native_go_fuzzer github.com/valyala/fasthttp FuzzResponseReadLimitBody fuzzResponseReadLimitBody
compile_native_go_fuzzer github.com/valyala/fasthttp FuzzRequestReadLimitBody fuzzRequestReadLimitBody
compile_native_go_fuzzer github.com/valyala/fasthttp FuzzURIUpdateBytes fuzzURIUpdateBytes
