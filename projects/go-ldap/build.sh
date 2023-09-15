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

go get github.com/AdamKorcz/go-118-fuzz-build/testing

compile_native_go_fuzzer github.com/go-ldap/ldap        FuzzParseDNv0                 fuzz_parse_dn_v0
compile_native_go_fuzzer github.com/go-ldap/ldap        FuzzDecodeEscapedSymbolsv0    fuzz_decode_escaped_symbols_v0
compile_native_go_fuzzer github.com/go-ldap/ldap        FuzzEscapeDNv0                fuzz_escape_dn_v0
compile_native_go_fuzzer github.com/go-ldap/ldap/v3     FuzzParseDNv3                 fuzz_parse_dn_v3
compile_native_go_fuzzer github.com/go-ldap/ldap/v3     FuzzDecodeEscapedSymbolsv3    fuzz_decode_escaped_symbols_v3
compile_native_go_fuzzer github.com/go-ldap/ldap/v3     FuzzEscapeDNv3                fuzz_escape_dn_v3
