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

zip "${OUT}/FuzzLoadCertificates_seed_corpus.zip" corpus/pem/*
zip "${OUT}/FuzzUnmarshalCertificatesFromPEM_seed_corpus.zip" corpus/pem/*
zip "${OUT}/FuzzUnmarshalPEMToPublicKey_seed_corpus.zip" corpus/pem/*
zip "${OUT}/FuzzED25529SignerVerfier_seed_corpus.zip" corpus/ed25519/*

rm go.mod
rm go.sum
cd $SRC/sigstore

go get github.com/AdamKorcz/go-118-fuzz-build/testing

compile_native_go_fuzzer github.com/sigstore/sigstore/test/fuzz FuzzGetPassword FuzzGetPassword
compile_native_go_fuzzer github.com/sigstore/sigstore/test/fuzz/pem FuzzLoadCertificates FuzzLoadCertificates
compile_native_go_fuzzer github.com/sigstore/sigstore/test/fuzz/pem FuzzUnmarshalCertificatesFromPEM FuzzUnmarshalCertificatesFromPEM
compile_native_go_fuzzer github.com/sigstore/sigstore/test/fuzz/pem FuzzUnmarshalPEMToPublicKey FuzzUnmarshalPEMToPublicKey
compile_native_go_fuzzer github.com/sigstore/sigstore/test/fuzz/signature FuzzECDSASigner FuzzECDSASigner
compile_native_go_fuzzer github.com/sigstore/sigstore/test/fuzz/signature FuzzComputeDigest FuzzComputeDigest
compile_native_go_fuzzer github.com/sigstore/sigstore/test/fuzz/signature FuzzComputeVerifying FuzzComputeVerifying
compile_native_go_fuzzer github.com/sigstore/sigstore/test/fuzz/signature FuzzED25529SignerVerfier FuzzED25529SignerVerfier
compile_native_go_fuzzer github.com/sigstore/sigstore/test/fuzz/signature FuzzRSAPKCS1v15SignerVerfier FuzzRSAPKCS1v15SignerVerfier
compile_native_go_fuzzer github.com/sigstore/sigstore/test/fuzz/signature FuzzRSAPSSSignerVerfier FuzzRSAPSSSignerVerfier
