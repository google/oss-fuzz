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

export FUZZER_DIR=$SRC/linkerd2/test/fuzzing

compile_go_fuzzer github.com/linkerd/linkerd2/pkg/profiles FuzzProfilesValidate FuzzProfilesValidate
compile_go_fuzzer github.com/linkerd/linkerd2/pkg/profiles FuzzRenderProto FuzzRenderProto
compile_go_fuzzer github.com/linkerd/linkerd2/controller/api/destination FuzzAdd FuzzAdd
compile_go_fuzzer github.com/linkerd/linkerd2/controller/api/destination FuzzGet FuzzGet
compile_go_fuzzer github.com/linkerd/linkerd2/controller/api/destination FuzzGetProfile FuzzGetProfile
compile_go_fuzzer github.com/linkerd/linkerd2/controller/api/destination FuzzProfileTranslatorUpdate FuzzProfileTranslatorUpdate
compile_go_fuzzer github.com/linkerd/linkerd2/pkg/healthcheck FuzzFetchCurrentConfiguration FuzzFetchCurrentConfiguration
compile_go_fuzzer github.com/linkerd/linkerd2/pkg/inject FuzzInject FuzzInject
compile_go_fuzzer github.com/linkerd/linkerd2/pkg/identity FuzzServiceCertify FuzzServiceCertify
compile_go_fuzzer github.com/linkerd/linkerd2/test/fuzzing FuzzParseContainerOpaquePorts FuzzParseContainerOpaquePorts
compile_go_fuzzer github.com/linkerd/linkerd2/test/fuzzing FuzzParsePorts FuzzParsePorts
compile_go_fuzzer github.com/linkerd/linkerd2/test/fuzzing FuzzHealthCheck FuzzHealthCheck
