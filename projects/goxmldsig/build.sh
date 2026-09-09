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

cd "${SRC}/goxmldsig"

# Register the go-118-fuzz-build testing dependency
printf "package dsig\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > registerfuzzdep.go
printf "package etreeutils\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > etreeutils/registerfuzzdep.go
go get github.com/AdamKorcz/go-118-fuzz-build/testing
go mod tidy

compile_native_go_fuzzer github.com/russellhaering/goxmldsig FuzzValidateXML FuzzValidateXML
compile_native_go_fuzzer github.com/russellhaering/goxmldsig FuzzCanonicalize FuzzCanonicalize
compile_native_go_fuzzer github.com/russellhaering/goxmldsig FuzzSignRoundTrip FuzzSignRoundTrip
compile_native_go_fuzzer github.com/russellhaering/goxmldsig FuzzValidateWithCert FuzzValidateWithCert
compile_native_go_fuzzer github.com/russellhaering/goxmldsig/etreeutils FuzzNSTraverse FuzzNSTraverse
compile_native_go_fuzzer github.com/russellhaering/goxmldsig/etreeutils FuzzTransformExcC14n FuzzTransformExcC14n
