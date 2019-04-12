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

make -j$(nproc) cmake_build

$CC $CFLAGS -Isrc -Ibuild/src -c $SRC/cmark/test/cmark-fuzz.c -o cmark_fuzzer.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE cmark_fuzzer.o build/src/libcmark.a -o $OUT/cmark_fuzzer

cp $SRC/*.options $OUT/
cp $SRC/cmark/test/fuzzing_dictionary $OUT/cmark.dict

mkdir -p corpus
cp $SRC/cmark/test/afl_test_cases/* corpus

git clone --depth 1 https://github.com/michelf/mdtest.git mdtest
find mdtest/*.mdtest -type f -name '*.text' | while read in_file
do
  # Genreate unique name for each input...
  out_file=$(sha1sum "$in_file" | cut -c 1-32)
  # ... and prepend a four-byte 'options' header
  printf "\0\0\0\0" > "corpus/$out_file"
  cat "$in_file" >> "corpus/$out_file"
done
zip -j $OUT/cmark_fuzzer_seed_corpus.zip corpus/*
