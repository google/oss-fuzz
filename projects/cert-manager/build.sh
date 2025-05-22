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

cp $SRC/pki_fuzzer.go $SRC/cert-manager/pkg/util/pki/

# These test files break the build, so removing; the fuzz tests don't need them
rm $SRC/cert-manager/pkg/controller/certificates/trigger/trigger_controller_test.go
rm $SRC/cert-manager/pkg/controller/certificates/revisionmanager/revisionmanager_controller_test.go

cd $SRC/go-118-fuzz-build
go build .
mv go-118-fuzz-build /root/go/bin/

cd $SRC/cert-manager
mkdir $SRC/cert-manager/pkg/fuzz
printf "package fuzz \nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > ./pkg/fuzz/fuzz-register.go
go mod tidy
go mod edit -replace github.com/AdamKorcz/go-118-fuzz-build=$SRC/go-118-fuzz-build
go mod tidy
compile_native_go_fuzzer github.com/cert-manager/cert-manager/internal/webhook/admission/certificaterequest/approval FuzzValidate FuzzValidate_approval
compile_native_go_fuzzer github.com/cert-manager/cert-manager/pkg/controller/certificates/trigger FuzzProcessItem FuzzProcessItem_trigger
compile_native_go_fuzzer github.com/cert-manager/cert-manager/pkg/controller/certificates/revisionmanager FuzzProcessItem FuzzProcessItem_revisionmanager
compile_native_go_fuzzer github.com/cert-manager/cert-manager/pkg/controller/certificates/issuing FuzzProcessItem FuzzProcessItem_issuing
compile_native_go_fuzzer github.com/cert-manager/cert-manager/pkg/controller/certificates/readiness FuzzProcessItem FuzzProcessItem_readiness
compile_native_go_fuzzer github.com/cert-manager/cert-manager/pkg/controller/certificates/keymanager FuzzProcessItem FuzzProcessItem_keymanager
compile_native_go_fuzzer github.com/cert-manager/cert-manager/pkg/controller/certificates/requestmanager FuzzProcessItem FuzzProcessItem_requestmanager
compile_native_go_fuzzer github.com/cert-manager/cert-manager/pkg/controller/certificaterequests/vault FuzzVaultCRController FuzzVaultCRController
compile_native_go_fuzzer github.com/cert-manager/cert-manager/pkg/controller/certificaterequests/venafi FuzzVenafiCRController FuzzVenafiCRController
compile_go_fuzzer github.com/cert-manager/cert-manager/pkg/util/pki FuzzUnmarshalSubjectStringToRDNSequence FuzzUnmarshalSubjectStringToRDNSequence
compile_go_fuzzer github.com/cert-manager/cert-manager/pkg/util/pki FuzzDecodePrivateKeyBytes FuzzDecodePrivateKeyBytes

