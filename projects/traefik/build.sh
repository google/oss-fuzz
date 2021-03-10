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

go mod download
rm $GOPATH/pkg/mod/go.elastic.co/apm@v1.7.0/gofuzz.go
rm $GOPATH/pkg/mod/go.elastic.co/apm@v1.7.0/model/gofuzz.go

mv $SRC/fuzzer.go ./pkg/rules/
compile_go_fuzzer ./pkg/rules Fuzz fuzz traefikfuzz

mv $SRC/server_fuzzer.go ./pkg/server/
compile_go_fuzzer ./pkg/server FuzzConnWrite fuzz_conn_write traefikfuzz


