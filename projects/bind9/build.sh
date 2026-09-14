#!/bin/sh -eu
# Copyright 2020 Google LLC
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

export CFLAGS="${CFLAGS} -fPIC"
export CXXFLAGS="${CXXFLAGS} -fPIC"

# Use the dedicated oss-fuzz fuzzing backend that BIND 9 provides.  It defines
# FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION (which drops the standalone main()
# from fuzz/main.c, so there is no duplicate-main conflict with the fuzzing
# engine) and links whatever engine OSS-Fuzz passes via $LIB_FUZZING_ENGINE.
# Building everything statically yields self-contained fuzzer binaries.
meson setup build \
  -Dfuzzing=enabled \
  -Dfuzzing-backend=oss-fuzz \
  -Doss-fuzz-args="$LIB_FUZZING_ENGINE" \
  -Db_lundef=false \
  -Dcmocka=enabled \
  -Dc_link_args="$CFLAGS" -Dcpp_link_args="$CXXFLAGS" \
  -Dc_args="$CFLAGS" -Dcpp_args="$CXXFLAGS" \
  -Ddefault_library=static -Dprefer_static=true \
  -Db_lto=false \
  -Dnamed-lto=disabled
meson compile -C build fuzz_dns_master_load fuzz_dns_message_checksig fuzz_dns_message_parse fuzz_dns_name_fromtext_target fuzz_dns_name_fromwire fuzz_dns_qp fuzz_dns_qpkey_name fuzz_dns_rdata_fromtext fuzz_dns_rdata_fromwire_text fuzz_isc_lex_getmastertoken fuzz_isc_lex_gettoken --verbose

for fuzzname in fuzz_dns_master_load fuzz_dns_message_checksig fuzz_dns_message_parse fuzz_dns_name_fromtext_target fuzz_dns_name_fromwire fuzz_dns_qp fuzz_dns_qpkey_name fuzz_dns_rdata_fromtext fuzz_dns_rdata_fromwire_text fuzz_isc_lex_getmastertoken fuzz_isc_lex_gettoken; do
  fuzzer_basename="${fuzzname:5}"
  fuzzer_name="${fuzzname:5}_fuzzer"
  cp build/${fuzzname} $OUT/${fuzzer_name}
  zip -j "${OUT}/${fuzzer_name}_seed_corpus.zip" ./fuzz/${fuzzer_basename}.in/* || true
done
