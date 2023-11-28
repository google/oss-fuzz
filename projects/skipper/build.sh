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

fuzz_targets=(FuzzParseEskip FuzzParseFilters FuzzParseIngressV1JSON
        FuzzParseIPCIDRs FuzzParseJwt FuzzParsePredicates
        FuzzParseRouteGroupsJSON FuzzServer)

for target in "${fuzz_targets[@]}"; do
        compile_go_fuzzer ./fuzz/fuzz_targets $target $target gofuzz
done

cp ./fuzz/dictionaries/* $OUT/
