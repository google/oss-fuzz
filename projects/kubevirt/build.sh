#!/bin/bash -eu
# Copyright 2024 Google LLC
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

cd "$SRC"/go-118-fuzz-build
go build .
mv go-118-fuzz-build /root/go/bin/
cd "$SRC"/kubevirt

printf "package webhooks\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > pkg/util/webhooks/register_fuzz_dep.go
go mod tidy
go mod vendor
go mod edit -replace github.com/AdamKorcz/go-118-fuzz-build="$SRC"/go-118-fuzz-build
go mod tidy
go mod vendor

mv $SRC/fuzz_test.go ./pkg/certificates/triple/cert/
compile_native_go_fuzzer kubevirt.io/kubevirt/pkg/certificates/triple/cert FuzzKeyParsers FuzzKeyParsers

mv $SRC/fuzz_loadInstallStrategyFromBytes_test.go ./pkg/virt-operator/resource/generate/install/
compile_native_go_fuzzer kubevirt.io/kubevirt/pkg/virt-operator/resource/generate/install FuzzLoadInstallStrategyFromBytes FuzzLoadInstallStrategyFromBytes
