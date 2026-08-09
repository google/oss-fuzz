#!/bin/bash -eu
# Copyright 2021 Google Inc.
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

# Bootstrap and configure project
./bootstrap --no-po
./configure --disable-shared --enable-debug --disable-nls
# Build project
make -j$(nproc) all
# Build fuzzer
cd fuzz
$CC $CFLAGS -c -I.. -I../src -I../tools -ogdbm_fuzzer.o gdbm_fuzzer.c
$CXX $CXXFLAGS -ogdbm_fuzzer gdbm_fuzzer.o ../tools/libgdbmapp.a ../src/.libs/libgdbm.a $LIB_FUZZING_ENGINE

cp gdbm_fuzzer $OUT
cp gdbm_fuzzer.rc $OUT

# Create seed
PATH=$SRC/gdbm/tools:$PATH sh ./build_seed.sh -C seed
zip -rj "$OUT/gdbm_fuzzer_seed_corpus.zip" seed/
