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
################################################################################

cd $SRC/crypto/ssh
cp $SRC/fuzz_test.go ./
compile_go_fuzzer golang.org/x/crypto/ssh FuzzParsePublicKey fuzz_parse_public_key
compile_go_fuzzer golang.org/x/crypto/ssh FuzzParseAuthorizedKey fuzz_parse_authorized_key
compile_go_fuzzer golang.org/x/crypto/ssh FuzzParseKnownHosts fuzz_parse_known_hosts
compile_go_fuzzer golang.org/x/crypto/ssh FuzzParsePrivateKey fuzz_parse_private_key
compile_go_fuzzer golang.org/x/crypto/ssh FuzzParsePrivateKeyWithPassphrase fuzz_parse_private_key_passphrase

