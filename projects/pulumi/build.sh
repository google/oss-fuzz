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

cd pkg
#go mod download

cp $SRC/schema_fuzzer.go $SRC/pulumi/pkg/codegen/schema/ 
compile_go_fuzzer github.com/pulumi/pulumi/pkg/v3/codegen/schema SchemaFuzzer schema_fuzzer

cp $SRC/config_fuzzer.go $SRC/pulumi/sdk/go/common/resource/config/
compile_go_fuzzer github.com/pulumi/pulumi/sdk/v3/go/common/resource/config FuzzConfig fuzz
compile_go_fuzzer github.com/pulumi/pulumi/sdk/v3/go/common/resource/config FuzzParseKey fuzz_parse_key
