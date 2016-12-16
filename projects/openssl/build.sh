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

./config enable-fuzz-libfuzzer -DPEDANTIC -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION no-shared enable-tls1_3 enable-rc5 enable-md2 enable-ec_nistp_64_gcc_128 enable-ssl3 enable-ssl3-method enable-nextprotoneg enable-weak-ssl-ciphers --with-fuzzer-lib=/usr/lib/libFuzzingEngine $CFLAGS -fno-sanitize=alignment

# openssl uses clang, not clang++ for linking. Add c++ libraries.
EX_LIBS="-ldl /usr/local/lib/libc++.a"
if [[ $SANITIZER = undefined ]]; then
	EX_LIBS="$EX_LIBS /usr/local/lib/clang/4.0.0/lib/linux/libclang_rt.ubsan_standalone_cxx-x86_64.a /usr/local/lib/clang/4.0.0/lib/linux/libclang_rt.ubsan_standalone-x86_64.a"
fi
make -j$(nproc) EX_LIBS="$EX_LIBS"

fuzzers=$(find fuzz -executable -type f '!' -name \*.py '!' -name \*-test)
for f in $fuzzers; do
	fuzzer=$(basename $f)
	cp $f $OUT/
	zip -j $OUT/${fuzzer}_seed_corpus.zip fuzz/corpora/${fuzzer}/*
done

cp $SRC/*.options $OUT/
