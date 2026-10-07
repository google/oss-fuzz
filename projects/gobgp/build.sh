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

sed -i '/func BenchmarkNormalizeFlowSpecOpValues(/,/^}/ s/^/\/\//' pkg/packet/bgp/bgp_test.go

compile_native_go_fuzzer $PWD/pkg/packet/rtr           FuzzParseRTR                fuzz_parse_rtr
compile_native_go_fuzzer $PWD/pkg/packet/bmp           FuzzParseBMPMessage         fuzz_parse_bmp_message
compile_native_go_fuzzer $PWD/pkg/packet/bgp           FuzzParseBGPMessage         fuzz_parse_bgp_message
compile_native_go_fuzzer $PWD/pkg/packet/bgp           FuzzParseLargeCommunity     fuzz_parse_large_community
compile_native_go_fuzzer $PWD/pkg/packet/bgp           FuzzParseFlowSpecComponents fuzz_parse_flow_spec_components
compile_native_go_fuzzer $PWD/pkg/packet/mrt           FuzzMRT                     fuzz_mrt
compile_native_go_fuzzer $PWD/pkg/zebra                FuzzZapi                    fuzz_zapi
