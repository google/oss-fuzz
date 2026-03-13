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

# build quickjs
# Makefile should not override CFLAGS
sed -i -e 's/CFLAGS=/CFLAGS+=/' Makefile
sed -i -e 's/#define USE_WORKER/\/\/#define USE_WORKER/' quickjs-libc.c
CONFIG_CLANG=y make libquickjs.fuzz.a .obj/fuzz_common.o .obj/libregexp.fuzz.o .obj/cutils.fuzz.o .obj/libunicode.fuzz.o
zip -r $OUT/fuzz_eval_seed_corpus.zip $SRC/quickjs-corpus/js/*.js
zip -r $OUT/fuzz_compile_seed_corpus.zip $SRC/quickjs-corpus/js/*.js

build_fuzz_target () {
    local target=$1
    shift
    $CC $CFLAGS -I. -c fuzz/$target.c -o $target.o
    $CXX $CXXFLAGS $target.o -o $OUT/$target $@ $LIB_FUZZING_ENGINE
}

build_fuzz_target fuzz_eval .obj/fuzz_common.o libquickjs.fuzz.a
build_fuzz_target fuzz_compile .obj/fuzz_common.o libquickjs.fuzz.a
build_fuzz_target fuzz_regexp .obj/libregexp.fuzz.o .obj/cutils.fuzz.o .obj/libunicode.fuzz.o

cp fuzz/fuzz.dict $OUT/fuzz_eval.dict
cp fuzz/fuzz.dict $OUT/fuzz_compile.dict
