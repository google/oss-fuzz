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

mkdir -p build && cd build
cmake -DRDK_BUILD_PYTHON_WRAPPERS=OFF -DLIB_FUZZING_ENGINE=${LIB_FUZZING_ENGINE} -DRDK_BUILD_FUZZ_TARGETS=ON -DRDK_INSTALL_STATIC_LIBS=ON -DBoost_USE_STATIC_LIBS=ON ..
make -j$(nproc)
make install

# Leave build directory
cd ..

# Copy the fuzzer executables, zip-ed corpora, options and dictionary files to $OUT
find . -type f -name '*_fuzzer' -exec cp -v '{}' $OUT ';'
find . -type f -name '*_fuzzer.dict' -exec cp -v '{}' $OUT ';'
#find . -type f -name '*_fuzzer.options' -exec cp -v '{}' $OUT ';'
corpora=$(find . -type d -name "*_fuzzer")
for corpus in $corpora; do
	corpus_basename=$(basename $corpus)
	zip -j $OUT/${corpus_basename}_seed_corpus.zip ${corpus}/*
done
