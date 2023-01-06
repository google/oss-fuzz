#!/bin/bash -eu
# Copyright 2023 Google LLC
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

sed 's/go 1.17/go 1.19/g' -i $SRC/notary/go.mod

cp $SRC/fuzz_trustmanager_test.go $SRC/notary/trustmanager/
printf "package trustmanager\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > $SRC/notary/trustmanager/registerfuzzdep.go
go mod tidy && go mod vendor
compile_go_fuzzer github.com/theupdateframework/notary/cryptoservice/fuzz Fuzz fuzz

mv $SRC/notary/trustmanager/keys_test.go $SRC/notary/trustmanager/keys_test_fuzz.go
mv $SRC/notary/trustmanager/keystore_test.go $SRC/notary/trustmanager/keystore_test_fuzz.go
compile_native_go_fuzzer github.com/theupdateframework/notary/trustmanager FuzzImportKeysSimple FuzzImportKeysSimple
compile_native_go_fuzzer github.com/theupdateframework/notary/trustmanager FuzzImportKeysStructured FuzzImportKeysStructured
