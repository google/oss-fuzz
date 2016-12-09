#!/bin/bash -eu
# Copyright 2016 Google Inc.
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

make bootstrap
./configure --enable-gcc-warnings --enable-static --with-included-libtasn1 --with-included-unistring --without-p11-kit --disable-doc
make "-j$(nproc)"

fuzzers="
client
x509_parser
"

for fuzzer in $fuzzers; do
    $CXX $CXXFLAGS -std=c++11 -Ilib/includes \
        "$SRC/gnutls_${fuzzer}_fuzzer.cc" -o "$OUT/gnutls_${fuzzer}_fuzzer" \
        lib/.libs/libgnutls.a -lFuzzingEngine -lpthread -Wl,-Bstatic \
        -lhogweed -lnettle -lgmp -Wl,-Bdynamic
done

cp "$SRC/gnutls_client_fuzzer_seed_corpus.zip" "$OUT/"
