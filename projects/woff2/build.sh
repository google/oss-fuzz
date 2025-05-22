#!/bin/bash -eu
# Copyright 2016 Google Inc.
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

if [ "$SANITIZER" == "introspector" ]; then
  cd $SRC/
  python3 -m pip install Brotli
  cd $SRC/woff2
fi

# Build the library. Actually there is no 'library' target, so we use .o files.
# '-no-canonical-prefixes' flag makes clang crazy. Need to avoid it.
cat brotli/shared.mk | sed -e "s/-no-canonical-prefixes//" \
> brotli/shared.mk.temp
mv brotli/shared.mk.temp brotli/shared.mk

if [ "$SANITIZER" == "introspector" ]; then
  # Modify AR flags as "f" is not a valid option to llvm-ar.
  sed -i 's/crf/cr/g' Makefile
fi

# woff2 uses LFLAGS instead of LDFLAGS.
make clean
make CC="$CC $CFLAGS" CXX="$CXX $CXXFLAGS" CANONICAL_PREFIXES= all \
  NOISY_LOGGING=

# Build fuzzers
for fuzzer_archive in src/*fuzzer*.a; do
  fuzzer_name=$(basename ${fuzzer_archive%.a})
  $CXX $CXXFLAGS $LIB_FUZZING_ENGINE $fuzzer_archive \
      -o $OUT/$fuzzer_name
  zip -q $OUT/${fuzzer_name}_seed_corpus.zip $SRC/corpus/*
done

cp $SRC/*.options $OUT/
