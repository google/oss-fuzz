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

rm lbclient_example_test.go
rm client_example_test.go
rm requestctx_setbodystreamwriter_example_test.go
rm fs_handler_example_test.go
rm server_example_test.go
rm fs_example_test.go
compile_native_go_fuzzer_v2 github.com/valyala/fasthttp FuzzCookieParse fuzzCookieParse
compile_native_go_fuzzer_v2 github.com/valyala/fasthttp FuzzVisitHeaderParams fuzzVisitHeaderParams
compile_native_go_fuzzer_v2 github.com/valyala/fasthttp FuzzResponseReadLimitBody fuzzResponseReadLimitBody
compile_native_go_fuzzer_v2 github.com/valyala/fasthttp FuzzRequestReadLimitBody fuzzRequestReadLimitBody
compile_native_go_fuzzer_v2 github.com/valyala/fasthttp FuzzURIUpdateBytes fuzzURIUpdateBytes
compile_native_go_fuzzer_v2 github.com/valyala/fasthttp FuzzURIParse fuzzURIParse
compile_native_go_fuzzer_v2 github.com/valyala/fasthttp FuzzTestHeaderScanner fuzzTestHeaderScanner
