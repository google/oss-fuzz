#!/bin/bash -eu
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0

cd $SRC/redis

# Build Redis with fuzzing flags
make CC="$CC" CFLAGS="$CFLAGS" MALLOC=libc BUILD_TLS=no \
    DISABLE_DEBUG=yes -j$(nproc) 2>&1 | tail -5

# Build fuzz_resp_parser
$CC $CFLAGS -I src -I deps/linenoise \
    $SRC/fuzz_resp_parser.c \
    src/resp_parser.o src/sds.o src/zmalloc.o \
    $LIB_FUZZING_ENGINE \
    -lpthread -lm \
    -o $OUT/fuzz_resp_parser

# Seed corpus for RESP3
mkdir -p $OUT/fuzz_resp_parser_seed_corpus
printf "+OK\r\n"                          > $OUT/fuzz_resp_parser_seed_corpus/simple_ok
printf "-ERR bad cmd\r\n"                 > $OUT/fuzz_resp_parser_seed_corpus/error
printf ":42\r\n"                          > $OUT/fuzz_resp_parser_seed_corpus/integer
printf "\$6\r\nfoobar\r\n"               > $OUT/fuzz_resp_parser_seed_corpus/bulk
printf "*2\r\n\$3\r\nfoo\r\n\$3\r\nbar\r\n" > $OUT/fuzz_resp_parser_seed_corpus/array
printf "_\r\n"                            > $OUT/fuzz_resp_parser_seed_corpus/null
printf "#t\r\n"                           > $OUT/fuzz_resp_parser_seed_corpus/bool_true

zip -j $OUT/fuzz_resp_parser_seed_corpus.zip $OUT/fuzz_resp_parser_seed_corpus/*
