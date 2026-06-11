# Copyright 2026 Google LLC
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

#!/bin/bash -eu
cd $SRC/lego
cp $SRC/fuzz_test.go ./
compile_go_fuzzer github.com/go-acme/lego/v5 FuzzParsePEMBundle fuzz_parse_pem_bundle
compile_go_fuzzer github.com/go-acme/lego/v5 FuzzParsePEMPrivateKey fuzz_parse_pem_private_key
compile_go_fuzzer github.com/go-acme/lego/v5 FuzzPEMDecodeToX509CSR fuzz_pem_decode_to_x509_csr
compile_go_fuzzer github.com/go-acme/lego/v5 FuzzParsePEMCertificate fuzz_parse_pem_certificate
compile_go_fuzzer github.com/go-acme/lego/v5 FuzzPEMDecode fuzz_pem_decode
