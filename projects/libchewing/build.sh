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

# build the library.
./autogen.sh
./configure --disable-shared --enable-static --without-sqlite3
make clean
make -j$(nproc) all

# build your fuzzer(s)
make -C test CFLAGS="$CFLAGS -Dmain=stress_main -Drand=get_fuzz_input" stress.o

$CC $CFLAGS -c $SRC/chewing_fuzzer_common.c -o $WORK/chewing_fuzzer_common.o

for variant in default random_init dynamic_config; do
    $CC $CFLAGS -c $SRC/chewing_${variant}_fuzzer.c -o $WORK/chewing_${variant}_fuzzer.o
    $CXX $CXXFLAGS \
      -o $OUT/chewing_${variant}_fuzzer \
      $WORK/chewing_${variant}_fuzzer.o $WORK/chewing_fuzzer_common.o \
      test/stress.o test/.libs/libtesthelper.a src/.libs/libchewing.a \
      $LIB_FUZZING_ENGINE
done

# install data files
make -j$(nproc) -C data pkgdatadir=$OUT install
