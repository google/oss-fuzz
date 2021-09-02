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

cd ext/yajl

echo '{"a":"\u00f8C","b":1.2,"c":{"d":["foo",{"bar":"baz"}]},"e":null,"f":true,"t":false}' > $WORK/seed.json
zip -q $OUT/json_fuzzer_seed_corpus.zip $WORK/seed.json

mv $SRC/*.dict $OUT/

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE -I. \
    -x c yajl.c yajl_alloc.c yajl_buf.c yajl_lex.c yajl_parser.c yajl_encode.c \
    ../../fuzz/json_fuzzer.c -o $OUT/json_fuzzer
