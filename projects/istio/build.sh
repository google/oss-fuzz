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

cd $SRC/go-118-fuzz-build
go build
mv go-118-fuzz-build $GOPATH/bin/go-118-fuzz-build_v2

pushd cmd/convertLibFuzzerTestcaseToStdLibGo
  go build . && mv convertLibFuzzerTestcaseToStdLibGo $GOPATH/bin/
popd
pushd cmd/addStdLibCorpusToFuzzer
  go build . && mv addStdLibCorpusToFuzzer $GOPATH/bin/
popd

cd $SRC/istio

cp $SRC/temp-istio/tests/fuzz/oss_fuzz_build.sh $SRC/istio/tests/fuzz/

# Build fuzzers
if [ -n "${OSS_FUZZ_CI-}" ]
then
	echo "Skipping most fuzzers since the OSS-fuzz CI may fail from running out of disk space."
	compile_go_fuzzer istio.io/istio/tests/fuzz FuzzCRDRoundtrip fuzz_crd_roundtrip
else
	$SRC/istio/tests/fuzz/oss_fuzz_build.sh
fi

