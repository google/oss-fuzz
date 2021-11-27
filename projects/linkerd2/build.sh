#!/bin/bash -eu
# Copyright 2021 Google LLC.
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


mkdir $SRC/linkerd2/test/fuzzing

mv $SRC/fuzzers.go $SRC/linkerd2/test/fuzzing/
mv $SRC/inject_fuzzer.go $SRC/linkerd2/pkg/inject/
mv $SRC/destination_fuzzer.go $SRC/linkerd2/controller/api/destination/
mv $SRC/linkerd2/controller/api/destination/endpoint_translator_test.go \
   $SRC/linkerd2/controller/api/destination/endpoint_translator_fuzz.go
mv $SRC/linkerd2/controller/api/destination/server_test.go \
   $SRC/linkerd2/controller/api/destination/server_fuzz.go
mv $SRC/healthcheck_fuzzer.go $SRC/linkerd2/pkg/healthcheck/
mv $SRC/identity_fuzzer.go $SRC/linkerd2/pkg/identity/
mv $SRC/linkerd2/pkg/identity/service_test.go \
   $SRC/linkerd2/pkg/identity/service_fuzz.go

compile_go_fuzzer github.com/linkerd/linkerd2/controller/api/destination FuzzAdd FuzzAdd
compile_go_fuzzer github.com/linkerd/linkerd2/controller/api/destination FuzzGetProfile FuzzGetProfile
compile_go_fuzzer github.com/linkerd/linkerd2/controller/api/destination FuzzProfileTranslatorUpdate FuzzProfileTranslatorUpdate
compile_go_fuzzer github.com/linkerd/linkerd2/controller/api/destination FuzzUpdateTrafficSplit FuzzUpdateTrafficSplit
compile_go_fuzzer github.com/linkerd/linkerd2/pkg/healthcheck FuzzFetchCurrentConfiguration FuzzFetchCurrentConfiguration
compile_go_fuzzer github.com/linkerd/linkerd2/pkg/inject FuzzParseMetaAndYAML FuzzParseMetaAndYAML
compile_go_fuzzer github.com/linkerd/linkerd2/pkg/identity FuzzServiceCertify FuzzServiceCertify
compile_go_fuzzer github.com/linkerd/linkerd2/test/fuzzing FuzzParseContainerOpaquePorts FuzzParseContainerOpaquePorts
compile_go_fuzzer github.com/linkerd/linkerd2/test/fuzzing FuzzParsePorts FuzzParsePorts
compile_go_fuzzer github.com/linkerd/linkerd2/test/fuzzing FuzzHealthCheck FuzzHealthCheck
