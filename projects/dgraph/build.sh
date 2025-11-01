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

mv $SRC/fuzz_parser_test.go $SRC/dgraph/dql/
printf "package dql\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > dql/register.go
go mod tidy
compile_native_go_fuzzer github.com/hypermodeinc/dgraph/v25/dql FuzzParserTest parser_fuzzer
