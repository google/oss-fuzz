#!/bin/bash -eu
# Copyright 2025 Google LLC
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

cd $SRC/redis

# Build Redis with fuzzing flags
# Use MALLOC=libc to avoid jemalloc issues in the fuzzing environment
# Disable TLS, Lua, and modules to reduce build complexity
make CC="$CC" CFLAGS="$CFLAGS -DFUZZ_BUILD" MALLOC=libc BUILD_TLS=no \
    DISABLE_DEBUG=yes -j$(nproc) 2>&1 | tail -5

# Extract object files needed for fuzz_resp_parser
RESP_OBJS="src/resp_parser.o src/sds.o src/zmalloc.o"

# Build fuzz_resp_parser: only needs resp_parser + sds + zmalloc
$CC $CFLAGS -I src -I deps/hiredis -I deps/linenoise \
    $SRC/fuzz_resp_parser.c \
    $RESP_OBJS \
    $LIB_FUZZING_ENGINE \
    -lpthread -lm \
    -o $OUT/fuzz_resp_parser

# Seed corpus: valid RESP3 messages
mkdir -p $OUT/fuzz_resp_parser_seed_corpus
echo -n "+OK\r\n"             > $OUT/fuzz_resp_parser_seed_corpus/simple_ok
echo -n "-ERR bad cmd\r\n"   > $OUT/fuzz_resp_parser_seed_corpus/error
echo -n ":42\r\n"            > $OUT/fuzz_resp_parser_seed_corpus/integer
echo -n "\$6\r\nfoobar\r\n"  > $OUT/fuzz_resp_parser_seed_corpus/bulk
echo -n "*2\r\n\$3\r\nfoo\r\n\$3\r\nbar\r\n" > $OUT/fuzz_resp_parser_seed_corpus/array
echo -n "_\r\n"              > $OUT/fuzz_resp_parser_seed_corpus/null
echo -n "#t\r\n"             > $OUT/fuzz_resp_parser_seed_corpus/bool_true
echo -n "#f\r\n"             > $OUT/fuzz_resp_parser_seed_corpus/bool_false
echo -n ",3.14\r\n"          > $OUT/fuzz_resp_parser_seed_corpus/double
echo -n "(12345678901234567890\r\n" > $OUT/fuzz_resp_parser_seed_corpus/big_num
echo -n "=15\r\ntxt:hello world\r\n" > $OUT/fuzz_resp_parser_seed_corpus/verbatim
echo -n "~3\r\n:1\r\n:2\r\n:3\r\n" > $OUT/fuzz_resp_parser_seed_corpus/set
echo -n "%2\r\n+key1\r\n:1\r\n+key2\r\n:2\r\n" > $OUT/fuzz_resp_parser_seed_corpus/map
zip -j $OUT/fuzz_resp_parser_seed_corpus.zip $OUT/fuzz_resp_parser_seed_corpus/*

# Dictionary for RESP3 tokens
cat > $OUT/fuzz_resp_parser.dict << 'DICT'
# RESP3 type prefixes
"+"
"-"
":"
"$"
"*"
"_"
","
"#t"
"#f"
"("
"="
"~"
"%"
"|"
">"
"\r\n"
"*-1"
"$-1"
DICT

echo "Build complete."
