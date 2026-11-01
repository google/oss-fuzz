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

# Native Go fuzz targets (func FuzzX(f *testing.F)) live next to the code
# they test in the toolhive repository.

# go-118-fuzz-build compiles every _test.go file in a fuzzed package, and some
# of them use an external _test package. The *_fuzz_test.go files are
# self-contained, so drop the other tests in those packages before building.
find pkg -name '*_fuzz_test.go' -printf '%h\n' | sort -u | while read -r dir; do
  find "$dir" -maxdepth 1 -name '*_test.go' ! -name '*_fuzz_test.go' -delete
done

compile_native_go_fuzzer_v2 github.com/stacklok/toolhive/pkg/mcp FuzzDecodeMessage fuzz_mcp_decode_message
compile_native_go_fuzzer_v2 github.com/stacklok/toolhive/pkg/auth/discovery FuzzParseWWWAuthenticate fuzz_discovery_parse_www_authenticate
compile_native_go_fuzzer_v2 github.com/stacklok/toolhive/pkg/auth/discovery FuzzExtractParameter fuzz_discovery_extract_parameter
compile_native_go_fuzzer_v2 github.com/stacklok/toolhive/pkg/auth/claims FuzzDecodeStringArray fuzz_claims_decode_string_array
compile_native_go_fuzzer_v2 github.com/stacklok/toolhive/pkg/auth/awssts FuzzExtractSessionName fuzz_awssts_extract_session_name
compile_native_go_fuzzer_v2 github.com/stacklok/toolhive/pkg/auth/sessionbinding FuzzParse fuzz_sessionbinding_parse
compile_native_go_fuzzer_v2 github.com/stacklok/toolhive/pkg/auth/sessionbinding FuzzFormat fuzz_sessionbinding_format
compile_native_go_fuzzer_v2 github.com/stacklok/toolhive/pkg/skills FuzzParseSkillMD fuzz_skills_parse_skill_md
compile_native_go_fuzzer_v2 github.com/stacklok/toolhive/pkg/plugins FuzzParsePluginManifestFromBytes fuzz_plugins_parse_manifest
compile_native_go_fuzzer_v2 github.com/stacklok/toolhive/pkg/runner FuzzReadJSON fuzz_runner_read_json
