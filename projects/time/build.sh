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

go install golang.org/x/tools/cmd/goimports@latest

go get github.com/AdamKorcz/go-118-fuzz-build/testing
go get github.com/stretchr/testify/assert@v1.7.0
go get github.com/facebook/time/fbclock/daemon


# FuzzCompute
sed -i -e '/func TestHashShouldMatch(/,/^}/ s/^/\/\//' leaphash/leaphash_test.go

# FuzzBytesToPacket
sed -i -e '/func Benchmark.*(/,/^}/ s/^/\/\//' ntp/protocol/ntp_test.go
goimports -w ntp/protocol/ntp_test.go

# FuzzDecodePacket ptp
sed -i -e '/func Benchmark.*(/,/^}/ s/^/\/\//' ptp/protocol/protocol_test.go


compile_native_go_fuzzer    github.com/facebook/time/fbclock/daemon          FuzzPrepareExpression       fuzz_prepare_expression
compile_native_go_fuzzer    github.com/facebook/time/leaphash                FuzzCompute                 fuzz_compute
compile_native_go_fuzzer    github.com/facebook/time/leapsectz               FuzzParse                   fuzz_parse
compile_native_go_fuzzer    github.com/facebook/time/ntp/chrony              FuzzDecodePacket            fuzz_decode_packet_ntp
compile_native_go_fuzzer    github.com/facebook/time/ntp/control             FuzzNormalizeData           fuzz_normalize_data
compile_native_go_fuzzer    github.com/facebook/time/ntp/protocol            FuzzBytesToPacket           fuzz_bytes_to_packet
compile_native_go_fuzzer    github.com/facebook/time/ptp/protocol            FuzzDecodePacket            fuzz_decode_packet_ptp
