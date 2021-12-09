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

# Notification-controller

# The notification-controller needs to be built with go 1.16
export OLD_PATH=$PATH
export PATH=/tmp/go/bin:$PATH
# We are now using go 1.16
cd $SRC/notification-controller/controllers
cp ../fuzzing/fuzz.go ./
rm *_test.go
compile_go_fuzzer . Fuzz notification_fuzzer
export PATH=$OLD_PATH

# Kustomize-controller:
cd $SRC/kustomize-controller
sed 's/filippo.io\/age v1.0.0-beta7/filippo.io\/age v1.0.0/g' -i go.mod
mv fuzz/fuzz.go ./controllers/
cd controllers
rm ./*_test.go
compile_go_fuzzer . Fuzz kustomize_fuzzer

# Pkg:
cd $SRC/pkg
mv ./fuzz/tls_fuzzer.go runtime/tls/
mv ./fuzz/conditions_fuzzer.go ./runtime/conditions/
go mod init pkg
cd fuzz
compile_go_fuzzer . FuzzUntar fuzz_untar
compile_go_fuzzer . FuzzLibGit2Error fuzz_libgit_2_error
compile_go_fuzzer . FuzzEventInfof fuzz_event_infof
cd -

cd ./runtime/tls
compile_go_fuzzer . FuzzTlsConfig fuzz_tls_config
cd -

cd ./runtime/conditions
compile_go_fuzzer . FuzzGetterConditions fuzz_getter_conditions
compile_go_fuzzer . FuzzConditionsMatch fuzz_conditions_match
compile_go_fuzzer . FuzzPatchApply fuzz_patch_apply
compile_go_fuzzer . FuzzConditionsUnstructured fuzz_conditions_unstructured
cd $SRC
