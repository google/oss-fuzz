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

# Prepare the project source for build.
./synclibs.sh
./autogen.sh
./configure --enable-shared=no

# Build the project and fuzzer binaries.
make -j$(nproc) LIB_FUZZING_ENGINE=${LIB_FUZZING_ENGINE}

# Copy the fuzzer binaries and test data to the output directory.
find ossfuzz -executable -type f -exec cp {} ${OUT} \;
(cd tests/data/ && zip ${OUT}/lznt1_fuzzer_seed_corpus.zip lznt1.*)
(cd tests/data/ && zip ${OUT}/lzx_fuzzer_seed_corpus.zip lzx.*)
(cd tests/data/ && zip ${OUT}/lzxpress_fuzzer_seed_corpus.zip lzxpress.*)
(cd tests/data/ && zip ${OUT}/lzxpress_huffman_fuzzer_seed_corpus.zip lzxpress_huffman.*)
(cd tests/data/ && zip ${OUT}/security_descriptor_fuzzer_seed_corpus.zip security_descriptor.*)
(cd tests/data/ && zip ${OUT}/security_identifier_fuzzer_seed_corpus.zip security_identifier.*)
