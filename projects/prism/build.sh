#!/bin/bash -eu
# Copyright 2026 Google LLC
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

cd $SRC/prism

# Generate templated C source files (ext/prism/api_node.c, include/prism/ast.h,
# src/diagnostic.c, etc.) that are not committed to git.
ruby templates/template.rb

# Build libprism.a with OSS-Fuzz sanitizer flags injected via $CC/$CFLAGS.
make static CC="$CC" CFLAGS="$CFLAGS"

# Copy our lex harness alongside the existing fuzz/parse.c from the project.
cp $SRC/fuzz_lex.c fuzz/lex.c

# Compile and link fuzz targets.
# fuzz/fuzz.c provides: LLVMFuzzerTestOneInput(data, size) -> harness(data, size)
# fuzz/parse.c and fuzz/lex.c each implement: harness(input, size)
for target in parse lex; do
  $CC $CFLAGS   -c fuzz/fuzz.c      -Iinclude -o /tmp/fuzz_driver.o
  $CC $CFLAGS   -c fuzz/${target}.c -Iinclude -o /tmp/fuzz_${target}.o
  $CXX $CXXFLAGS /tmp/fuzz_driver.o /tmp/fuzz_${target}.o \
      build/libprism.a $LIB_FUZZING_ENGINE \
      -o $OUT/fuzz_${target}
done

# Dictionary: use prism's own fuzz/dict (Ruby keywords, operators, magic tokens).
cp fuzz/dict $OUT/fuzz_parse.dict
cp fuzz/dict $OUT/fuzz_lex.dict

# Seed corpus: all Ruby fixture files from the test suite.
# find (not glob) to include all subdirectories (~986 files vs ~107 at top level).
# Relative paths without -j to avoid basename collisions across subdirs.
find test/prism/fixtures -name '*.txt' | \
    xargs zip $OUT/fuzz_parse_seed_corpus.zip
cp $OUT/fuzz_parse_seed_corpus.zip $OUT/fuzz_lex_seed_corpus.zip
