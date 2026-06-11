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

cp $SRC/fuzz_test.go $SRC/protobuf-go/encoding/protowire/

cd $SRC/protobuf-go

compile_go_fuzzer google.golang.org/protobuf/encoding/protowire FuzzConsumeTag FuzzConsumeTag
compile_go_fuzzer google.golang.org/protobuf/encoding/protowire FuzzWireRoundTrip FuzzWireRoundTrip
compile_go_fuzzer google.golang.org/protobuf/encoding/protowire FuzzVarintRoundTrip FuzzVarintRoundTrip
compile_go_fuzzer google.golang.org/protobuf/encoding/protowire FuzzConsumeField FuzzConsumeField
