#!/bin/bash -eu
# Copyright 2021 Google LLC
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

./configure --static-build --extra-cflags="${CFLAGS}" --extra-ldflags="${CFLAGS}"
make


fuzzers=$(find $SRC/gpac/testsuite/oss-fuzzers -name "fuzz_*.c")
for f in $fuzzers; do

    fuzzerName=$(basename $f .c)
    echo "Building fuzzer $fuzzerName"

    $CC $CFLAGS -I./include -I./ -DGPAC_HAVE_CONFIG_H -c $f
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE $fuzzerName.o -o $OUT/$fuzzerName \
      ./bin/gcc/libgpac_static.a \
      -lm -lz -lpthread -lssl -lcrypto -DGPAC_HAVE_CONFIG_H


    if [ -d "$SRC/gpac/testsuite/oss-fuzzers/${fuzzerName}_corpus" ]; then
        zip -j $OUT/${fuzzerName}_seed_corpus.zip $SRC/gpac/testsuite/oss-fuzzers/${fuzzerName}_corpus/*
    fi

done