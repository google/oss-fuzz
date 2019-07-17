#!/bin/bash -eu
# Copyright 2017 Google Inc.
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

./autogen.sh

./configure CFLAGS="$CFLAGS -DNO_CHECK_MEMWIPE" \
	--enable-imc-test \
	--enable-tnccs-20 \
	--enable-fuzzing \
	--with-libfuzzer=$LIB_FUZZING_ENGINE \
	--enable-monolithic \
	--disable-shared \
	--enable-static

make -j$(nproc)

fuzzers=$(find fuzz -maxdepth 1 -executable -type f -name 'fuzz_*')
for f in $fuzzers; do
	fuzzer=$(basename $f)
	cp $f $OUT/
	corpus=${fuzzer#fuzz_}
	if [ -d "fuzzing-corpora/${corpus}" ]; then
		zip -rj $OUT/${fuzzer}_seed_corpus.zip fuzzing-corpora/${corpus}
	fi
done
