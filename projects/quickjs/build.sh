#!/bin/bash -eu
# Copyright 2018 Google Inc.
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

# build quickjs
cd quickjs
# Makefile should not override CFLAGS
sed -i -e 's/CFLAGS=/CFLAGS+=/' Makefile
if [ "$ARCHITECTURE" = 'i386' ]; then
    export CFLAGS="$CFLAGS -m32"
fi
CONFIG_CLANG=y make libquickjs.a
zip -r $OUT/fuzz_eval_seed_corpus.zip tests/*.js
zip -r $OUT/fuzz_eval_seed_corpus.zip examples/*.js
zip -r $OUT/fuzz_compile_seed_corpus.zip tests/*.js
zip -r $OUT/fuzz_compile_seed_corpus.zip examples/*.js

cd ..
$CC $CFLAGS -Iquickjs -c fuzz_eval.c -o fuzz_eval.o
$CXX $CXXFLAGS fuzz_eval.o -o $OUT/fuzz_eval quickjs/libquickjs.a $LIB_FUZZING_ENGINE
$CC $CFLAGS -Iquickjs -c fuzz_compile.c -o fuzz_compile.o
$CXX $CXXFLAGS fuzz_compile.o -o $OUT/fuzz_compile quickjs/libquickjs.a $LIB_FUZZING_ENGINE
$CC $CFLAGS -Iquickjs -c fuzz_regexp.c -o fuzz_regexp.o
$CXX $CXXFLAGS fuzz_regexp.o -o $OUT/fuzz_regexp quickjs/libquickjs.a $LIB_FUZZING_ENGINE

