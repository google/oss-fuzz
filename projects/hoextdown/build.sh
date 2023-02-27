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

# temporary hack to make the build honor CFLAGS. Needs proper fix upstream.
sed -i 's/^CFLAGS.*//g' Makefile
# build project
make -j$(nproc) libhoedown.a

# build fuzzers
$CC $CFLAGS -c -std=c99 -Isrc \
    "$SRC/hoextdown/test/hoedown_fuzzer.c" -o $WORK/hoedown_fuzzer.o
$CXX $CXXFLAGS -std=c++11 -Isrc \
    $WORK/hoedown_fuzzer.o -o $OUT/hoedown_fuzzer \
    $LIB_FUZZING_ENGINE "$SRC/hoextdown/libhoedown.a"

cp $SRC/*.options $OUT/
cp $SRC/*.dict $OUT/

# build corpus
mkdir -p corpus
find $SRC/hoextdown/test -type f -name '*.text' | while read in_file
do
  # Genreate unique name for each input...
  out_file=$(sha1sum "$in_file" | cut -c 1-32)
  cat "$in_file" >> "corpus/$out_file"
done

zip -j $OUT/hoextdown_fuzzer_corpus.zip corpus/*
