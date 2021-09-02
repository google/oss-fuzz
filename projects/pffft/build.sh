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

SRC_DIR=$SRC/pffft
cd $WORK

# Deploy the seed corpus.
SEED_CORPUS_ZIP_PATH=$OUT/pffft_fuzzers_seed_corpus.zip
if [ -d seed_corpus_tmp ]; then 
  rm -fr seed_corpus_tmp
fi
mkdir seed_corpus_tmp
python $SRC_DIR/generate_seed_corpus.py seed_corpus_tmp
cd seed_corpus_tmp
zip -q $SEED_CORPUS_ZIP_PATH ./*
cd ..
rm -fr seed_corpus_tmp

build_fuzzer() {
  # Aliases for the arguments.
  fft_transform=$1

  # Fuzzer name.
  fuzz_target_name=pffft_${fft_transform,,}_fuzzer

  # Add a symbolic link for the seed corpus (same corpus for all the
  # generated fuzzers).
  ls -la $OUT/*.zip
  FUZZER_SEED_CORPUS_PATH=$OUT/${fuzz_target_name}_seed_corpus.zip
  if [ -e $FUZZER_SEED_CORPUS_PATH ]; then
    rm $FUZZER_SEED_CORPUS_PATH
  fi
  ln -s $SEED_CORPUS_ZIP_PATH $FUZZER_SEED_CORPUS_PATH

  # Compile fuzzer.
  $CXX $CXXFLAGS -std=c++11 -msse2 \
       -DTRANSFORM_${fft_transform} \
       $SRC/pffft/pffft.c $SRC/pffft/pffft_fuzzer.cc \
       -o $OUT/${fuzz_target_name} \
       $LIB_FUZZING_ENGINE
}

# Build fuzzers.
build_fuzzer REAL
build_fuzzer COMPLEX
