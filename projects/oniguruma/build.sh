#!/bin/bash -eu
# Copyright 2020 Google Inc.
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

# build project
./autogen.sh
./configure
make clean
make -j$(nproc)

FUZZ_SRCDIR=harnesses
FUZZ_TARGET=fuzzer

# build fuzzer
$CC $CFLAGS -o $FUZZ_SRCDIR/fuzzer_syntax.o -I src -c -DSYNTAX_TEST $FUZZ_SRCDIR/base.c
$CXX $CXXFLAGS -o $OUT/$FUZZ_TARGET $FUZZ_SRCDIR/fuzzer_syntax.o $LIB_FUZZING_ENGINE src/.libs/libonig.a

# setup files
cp $FUZZ_SRCDIR/$FUZZ_TARGET.options $OUT/
cp $FUZZ_SRCDIR/ascii_compatible.dict $OUT/$FUZZ_TARGET.dict
