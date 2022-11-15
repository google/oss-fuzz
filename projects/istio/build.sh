#!/bin/bash -eu
# Copyright 2020 Google Inc.
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

cd $SRC
git clone --branch=dev https://github.com/AdamKorcz/go-118-fuzz-build $SRC/go-118-fuzz-build
cd $SRC/istio
go mod edit -replace github.com/AdamKorcz/go-118-fuzz-build=/src/go-118-fuzz-build
find $SRC/istio -type f -exec sed -i 's/AdamKorcz\/go-118-fuzz-build\/utils/AdamKorcz\/go-118-fuzz-build\/testing/g' {} \;
sed -i 's/\"testing\"/\"github.com\/AdamKorcz\/go-118-fuzz-build\/testing\"/g' $SRC/istio/pkg/fuzz/util.go
cat $SRC/istio/pkg/fuzz/util.go


if [ -n "${OSS_FUZZ_CI-}" ]
then
	echo "Skipping most fuzzers since the OSS-fuzz CI may fail from running out of disk space."
	mv ./tests/fuzz/kube_gateway_controller_fuzzer.go ./pilot/pkg/config/kube/gateway/
	compile_go_fuzzer istio.io/istio/pilot/pkg/config/kube/gateway ConvertResourcesFuzz fuzz_convert_resources
else
	$SRC/istio/tests/fuzz/oss_fuzz_build.sh
fi


