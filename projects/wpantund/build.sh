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

# Wpantund's configure script is fuzzer-aware, so we
# move those flags into their own environment variables.
FUZZ_CFLAGS="${CFLAGS}"
FUZZ_CXXFLAGS="${CXXFLAGS}"
unset CFLAGS
unset CXXFLAGS

./bootstrap.sh

./configure                               \
        --enable-fuzz-targets             \
        --disable-shared                  \
        --enable-static                   \
		CC="${CC}"                        \
		CXX="${CXX}"                      \
		FUZZ_LIBS="${LIB_FUZZING_ENGINE}" \
		FUZZ_CFLAGS="${FUZZ_CFLAGS}"      \
		FUZZ_CXXFLAGS="${FUZZ_CXXFLAGS}"  \
		LDFLAGS="-lpthread"               \
		CXXFLAGS="-stdlib=libc++"

# Build everything.
make -j$(nproc)

# Copy all fuzzers and related options/dictionaries.
find . -name '*[-_]fuzz' -type f -exec cp -v '{}' $OUT ';'
find . -name '*[-_]fuzz.dict' -type f -exec cp -v '{}' $OUT ';'
find . -name '*[-_]fuzz.options' -type f -exec cp -v '{}' $OUT ';'

# Copy all of the fuzzers' related corpi.
for f in etc/fuzz-corpus/*[-_]fuzz
do
    fuzzer=$(basename $f)
    if test -d "${f}"
	then zip -j $OUT/${fuzzer}_seed_corpus.zip ${f}/*
    fi
done

# Dump out all of the files in the output.
find $OUT -type f > /dev/stderr
