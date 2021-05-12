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

git apply $SRC/fuzz_diff.patch
mkdir build-dir && cd build-dir

cmake -DZSTD=TRUE \
	  -DSTATIC=TRUE \
	  -DOSS_FUZZ=ON \
	  -DEMSCRIPTEN=FALSE \
	  -DOSS_FUZZ=TRUE \
	   ..
make -j$(nproc)

find . -name "*.o" -exec ar rcs fuzz_lib.a {} \;

$CXX $CXXFLAGS  -I$SRC/basis_universal/transcoder \
	-c $SRC/basisu_fuzzer.cpp -o fuzzer.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
	-DBASISD_SUPPORT_KTX2_ZSTD=1 fuzzer.o -o $OUT/fuzzer \
	fuzz_lib.a

zip $OUT/fuzzer_seed_corpus.zip \
	$SRC/basis_universal/webgl/texture/assets/*
