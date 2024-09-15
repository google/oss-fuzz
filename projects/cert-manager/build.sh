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

cp -r $SRC/pki_fuzzer.go $SRC/cert-manager/pkg/util/pki/

cd $SRC
git clone --depth=1 https://github.com/AdamKorcz/go-118-fuzz-build --branch=include-all-test-files
cd go-118-fuzz-build
ls $HOME/go/pkg/mod/github.com/
go build .
mv go-118-fuzz-build /root/go/bin/

cd $SRC/cert-manager
go get github.com/AdamKorcz/go-118-fuzz-build/testing@include-all-test-files

compile_native_go_fuzzer github.com/cert-manager/cert-manager/pkg/controller/certificaterequests/vault FuzzVaultSync FuzzVaultSync
compile_go_fuzzer github.com/cert-manager/cert-manager/pkg/util/pki FuzzUnmarshalSubjectStringToRDNSequence FuzzUnmarshalSubjectStringToRDNSequence
compile_go_fuzzer github.com/cert-manager/cert-manager/pkg/util/pki FuzzDecodePrivateKeyBytes FuzzDecodePrivateKeyBytes

