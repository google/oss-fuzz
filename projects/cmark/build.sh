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

$CC $CFLAGS -Isrc -Ibuild/src -c $SRC/markdown_to_html_fuzzer.c -o $WORK/markdown_to_html_fuzzer.o
$CXX $CXXFLAGS -lFuzzingEngine $WORK/markdown_to_html_fuzzer.o build/src/libcmark.a -o $OUT/markdown_to_html_fuzzer

cp $SRC/*.options $OUT/
zip -j $OUT/markdown_to_html_fuzzer.zip $SRC/cmark/test/afl_test_cases/*

# TODO: convert upstream AFL dictionary to new format
# Convert the old AFL dictionary format to the new libFuzzer format
afl_dir="test/afl_dictionary/"
if [ -d "$afl_dir" ]; then
  truncate --size 0 $OUT/cmark.dict
  # For each individual token...
  for filename in $(find "$afl_dir" -type f -size +0); do
    # ... hex escape ...
    token=$(cat "$filename" | od -v -An -tx1 | tr -d '\n' | sed -e 's/ /\\x/g')
    # ...then surround by double-quotes
    echo "\"$token\"" >> $OUT/cmark.dict
  done
fi
