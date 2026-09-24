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

cd $SRC/go-jose

# Upstream (ana repo) tarafından eklenen fuzzer'ları derle
compile_go_fuzzer github.com/go-jose/go-jose/v3/fuzz FuzzJWSParse fuzz_jws_parse
compile_go_fuzzer github.com/go-jose/go-jose/v3/fuzz FuzzJWSParseCompact fuzz_jws_parse_compact
compile_go_fuzzer github.com/go-jose/go-jose/v3/fuzz FuzzJWSParseDetached fuzz_jws_parse_detached
compile_go_fuzzer github.com/go-jose/go-jose/v3/fuzz FuzzJWEParse fuzz_jwe_parse
compile_go_fuzzer github.com/go-jose/go-jose/v3/fuzz FuzzJWEParseCompact fuzz_jwe_parse_compact
compile_go_fuzzer github.com/go-jose/go-jose/v3/fuzz FuzzJWTParse fuzz_jwt_parse
compile_go_fuzzer github.com/go-jose/go-jose/v3/fuzz FuzzJWTParseSigned fuzz_jwt_parse_signed
compile_go_fuzzer github.com/go-jose/go-jose/v3/fuzz FuzzJWTParseEncrypted fuzz_jwt_parse_encrypted
