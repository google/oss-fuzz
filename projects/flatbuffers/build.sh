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

# Build fuzzer only
cd $SRC/flatbuffers
mkdir build
cd build
cmake -DOSS_FUZZ:BOOL=ON -G "Unix Makefiles" ../tests/fuzzer
make

cp ../tests/fuzzer/*.dict $OUT/
cp *.bfbs $OUT/
cp *_fuzzer $OUT/

# Build unit test
mkdir $SRC/flatbuffers/build-tests
cd $SRC/flatbuffers/build-tests
cmake -DFLATBUFFERS_BUILD_FLATC=ON -DFLATBUFFERS_BUILD_TESTS=ON ..
make flattests -j$(nproc)

# Build the Rust fuzzer only
#
# The Rust runtime's verifier and the generated safe accessors are a separate
# implementation from the C++ one fuzzed above, so they get a target of their own.
#
# The Rust tooling supports the address sanitizer and libFuzzer only (see
# docs/getting-started/new-project-guide/rust_lang.md), so the target is built
# for that combination only and the existing MSan/UBSan/AFL builds of the C++
# fuzzers above are left exactly as they were.
if [ "$SANITIZER" = "address" ] && [ "$FUZZING_ENGINE" = "libfuzzer" ]; then
  # The bindings for rust_verifier_fuzzer/*.fbs are generated here, with the
  # flatc built from this same checkout, so that the target always exercises the
  # current code generator: a checked-in copy of the generated code would keep
  # testing whatever the generator produced on the day it was copied.
  cd $SRC/flatbuffers/build-tests
  make flatc -j$(nproc)
  ./flatc --rust -o $SRC/rust_verifier_fuzzer/src \
      $SRC/rust_verifier_fuzzer/flatbuffers_rust_verifier.fbs

  cd $SRC/rust_verifier_fuzzer
  cargo fuzz build -O
  cp fuzz/target/x86_64-unknown-linux-gnu/release/flatbuffers_rust_verifier $OUT/

  # Start the fuzzer off from well formed buffers of the schema above, so it does
  # not have to rediscover the wire format from an empty corpus.
  zip -j $OUT/flatbuffers_rust_verifier_seed_corpus.zip $SRC/rust_verifier_fuzzer/seed/*
fi
