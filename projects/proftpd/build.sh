#!/bin/bash -eu
# Copyright 2021 Google LLC.
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

export LDFLAGS="${CFLAGS}"
./configure --enable-ctrls
make -j$(nproc)

# We need a few declarations from main.c
# so we rename main() to main2()
sed 's/int main(/int main2(/g' -i $SRC/proftpd/src/main.c

# Compile main.c again
export NEW_CC_FLAG="${CC} ${CFLAGS} -DHAVE_CONFIG_H -DLINUX  -I. -I./include"
$NEW_CC_FLAG -c src/main.c -o src/main.o
rm src/ftpdctl.o

find . -name "*.o" -exec ar rcs fuzz_lib.a {} \;

# Build fuzzer(s)
$NEW_CC_FLAG -c $SRC/fuzzer.c -o fuzzer.o
$CC $CXXFLAGS $LIB_FUZZING_ENGINE fuzzer.o -o $OUT/fuzzer \
	src/scoreboard.o \
	lib/prbase.a \
	fuzz_lib.a \
	-L/src/proftpd/lib \
	-lcrypt -pthread

# Build seed corpus
cd $SRC
git clone https://github.com/dvyukov/go-fuzz-corpus
zip $OUT/fuzzer_seed_corpus.zip go-fuzz-corpus/json/corpus/*

