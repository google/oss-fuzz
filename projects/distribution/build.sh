#!/bin/bash -eu
# Copyright 2021 Google LLC
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

mv $SRC/reference_fuzzer.go $SRC/distribution/reference/
compile_go_fuzzer github.com/distribution/distribution/v3/reference FuzzParseNormalizedNamed fuzz_parsed_normalized_named
mv $SRC/api_v2_fuzzer.go $SRC/distribution/registry/api/v2/
compile_go_fuzzer github.com/distribution/distribution/v3/registry/api/v2/ FuzzParseForwardedHeader fuzz_parse_forwarded_header
