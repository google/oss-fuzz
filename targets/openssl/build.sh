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

./config enable-fuzz-libfuzzer -DPEDANTIC no-shared --with-fuzzer-lib=/usr/lib/libfuzzer $CFLAGS
make -j$(nproc) EX_LIBS="-ldl /usr/local/lib/libc++.a"

fuzzers=$(find fuzz -executable -type f '!' -name \*.py '!' -name \*-test)
for f in $fuzzers; do
	fuzzer=$(basename $f)
	cp $f $OUT/
	zip -j $OUT/${fuzzer}_seed_corpus.zip fuzz/corpora/${fuzzer}/*
done

