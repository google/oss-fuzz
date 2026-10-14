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

FUZZERS="fuzz_bos_descriptor fuzz_control_setup fuzz_descriptor_parsers"

# build project
./autogen.sh
./configure --disable-shared --enable-fuzzers
make -j$(nproc) all

# collect the fuzzers
for fuzzer in $FUZZERS; do
    cp tests/fuzz/$fuzzer $OUT/
done

# seed corpora
zip -j -q $OUT/fuzz_bos_descriptor_seed_corpus.zip tests/fuzz/corpus/bos/*
zip -j -q $OUT/fuzz_descriptor_parsers_seed_corpus.zip tests/fuzz/corpus/descriptor_parsers/*
