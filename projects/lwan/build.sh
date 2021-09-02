#!/bin/bash -euv
# Copyright 2019 Google Inc.
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


mkdir -p $WORK/lwan
cd $WORK/lwan

cmake -GNinja \
	-DCMAKE_BUILD_TYPE=Debug \
	-DCMAKE_C_COMPILER="${CC}" \
	-DCMAKE_C_FLAGS="${CFLAGS}" \
	$SRC/lwan/

ninja -v liblwan.a

cp $SRC/lwan/fuzz/*.dict $OUT/

for fuzzer in $SRC/lwan/src/bin/fuzz/*_fuzzer.cc; do
	executable=$(basename $fuzzer .cc)
	corpus_base=$(basename $fuzzer _fuzzer.cc)

	zip -jr $OUT/${executable}_seed_corpus.zip $SRC/lwan/fuzz/corpus/corpus-${corpus_base}-*
	
	$CXX $CXXFLAGS -std=c++11 \
		-Wl,-whole-archive $WORK/lwan/src/lib/liblwan.a -Wl,-no-whole-archive \
		-I$SRC/lwan/src/lib $fuzzer \
		$LIB_FUZZING_ENGINE -lpthread -lz \
		-o $OUT/$executable
done
