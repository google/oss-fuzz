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

TARGET_PATH="./fuzz/target/x86_64-unknown-linux-gnu/release"
BASE="$SRC/linkerd2-proxy/linkerd"
BUILD_FUZZER="cargo +nightly fuzz build --features fuzzing"

cd ${BASE}/app/inbound
${BUILD_FUZZER}
cp ${TARGET_PATH}/fuzz_target_1 $OUT/fuzz_inbound

cd ${BASE}/addr/
${BUILD_FUZZER}
cp ${TARGET_PATH}/fuzz_target_1 $OUT/fuzz_addr

cd ${BASE}/dns
${BUILD_FUZZER}
cp ${TARGET_PATH}/fuzz_target_1 $OUT/fuzz_dns

cd ${BASE}/proxy/http
${BUILD_FUZZER}
cp ${TARGET_PATH}/fuzz_target_1 $OUT/fuzz_http

cd ${BASE}/tls
${BUILD_FUZZER}
cp ${TARGET_PATH}/fuzz_target_1 $OUT/fuzz_tls

cd ${BASE}/transport-header
${BUILD_FUZZER}
cp ${TARGET_PATH}/fuzz_target_raw $OUT/fuzz_transport_raw
cp ${TARGET_PATH}/fuzz_target_structured $OUT/fuzz_transport_structured
