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

# Create seed corpus for string_encode_fuzzer
echo 'Hello, world!' > $WORK/seed1.txt
echo '{"key": "value with \u2028 and \u2029"}' > $WORK/seed2.txt
echo '<script>alert("xss")</script>' > $WORK/seed3.txt
zip -q $OUT/string_encode_fuzzer_seed_corpus.zip $WORK/seed*.txt

# Create seed corpus for parse complete fuzzer
echo '123' > $WORK/pc_seed1.json
echo '{"number": 123' > $WORK/pc_seed2.json
echo '[1,2,3' > $WORK/pc_seed3.json
echo '{"value": 123.456e+10' > $WORK/pc_seed4.json
echo '{"array": [1,2,3.14159' > $WORK/pc_seed5.json
echo '{"mixed": [1, true, null, -123.456, {"nested": 42' > $WORK/pc_seed6.json
zip -q $OUT/parse_complete_fuzzer_seed_corpus.zip $WORK/pc_seed*.json

# Create seed corpus for lex peek fuzzer
echo '{"test": 123}' > $WORK/peek1.json
echo '[1,2,3]' > $WORK/peek2.json
echo 'true' > $WORK/peek3.json
echo '"string with \\u2028"' > $WORK/peek4.json
echo '/* comment */ {"a":1}' > $WORK/peek5.json
zip -q $OUT/lex_peek_fuzzer_seed_corpus.zip $WORK/peek*.json

# Create seed corpus
echo '{"test": 123' > $WORK/error1.json
echo '[1,2,3' > $WORK/error2.json
echo '{"key":}' > $WORK/error3.json
echo 'invalid' > $WORK/error4.json
echo '/* unclosed comment' > $WORK/error5.json
zip -q $OUT/error_string_fuzzer_seed_corpus.zip $WORK/error*.json

mv $SRC/*.dict $OUT/

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE -I. \
    -x c yajl.c yajl_alloc.c yajl_buf.c yajl_lex.c yajl_parser.c yajl_encode.c \
    ../../fuzz/json_fuzzer.c -o $OUT/json_fuzzer

# Build string encode fuzzer
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE -I. \
    -x c yajl.c yajl_alloc.c yajl_buf.c yajl_lex.c yajl_parser.c yajl_encode.c \
    ../../fuzz/string_encode_fuzzer.c -o $OUT/string_encode_fuzzer

# Build parse complete fuzzer
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE -I. \
    -x c yajl.c yajl_alloc.c yajl_buf.c yajl_lex.c yajl_parser.c yajl_encode.c \
    ../../fuzz/parse_complete_fuzzer.c -o $OUT/parse_complete_fuzzer

# Build lex peek fuzzer
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE -I. \
    -x c yajl.c yajl_alloc.c yajl_buf.c yajl_lex.c yajl_parser.c yajl_encode.c \
    ../../fuzz/lex_peek_fuzzer.c -o $OUT/lex_peek_fuzzer

# Build error string fuzzer
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE -I. \
    -x c yajl.c yajl_alloc.c yajl_buf.c yajl_lex.c yajl_parser.c yajl_encode.c \
    ../../fuzz/error_string_fuzzer.c -o $OUT/error_string_fuzzer
