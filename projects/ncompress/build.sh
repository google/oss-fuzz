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
################################################################################

# The harness #includes compress.c directly (ncompress is a single-file program
# whose functions are static), with its main() renamed out of the way. exit()
# is wrapped so the target's corrupt-input exit(1) returns into the harness
# instead of terminating the fuzzer; genuine sanitizer aborts are unaffected.
cp $SRC/fuzz_ncompress.c $SRC/ncompress/

$CC $CFLAGS -I. -c \
    -Dmain=ncompress_cli_main \
    $SRC/ncompress/fuzz_ncompress.c -o fuzz_ncompress.o

$CXX $CXXFLAGS fuzz_ncompress.o -Wl,--wrap=exit \
    $LIB_FUZZING_ENGINE -o $OUT/fuzz_ncompress

# Seed corpus: build ncompress once (uninstrumented) and compress a few inputs.
mkdir -p seeds
cc -O2 -w compress.c -o /tmp/ncompress_seedgen || true
if [ -x /tmp/ncompress_seedgen ]; then
  printf 'hello hello world world ncompress lzw test test test\n' \
      | /tmp/ncompress_seedgen -c > seeds/hello.Z 2>/dev/null || true
  head -c 4000 /dev/urandom | /tmp/ncompress_seedgen -c > seeds/rand.Z 2>/dev/null || true
  python3 -c "import sys;sys.stdout.buffer.write(b'A'*5000)" \
      | /tmp/ncompress_seedgen -c > seeds/runs.Z 2>/dev/null || true
fi
zip -j $OUT/fuzz_ncompress_seed_corpus.zip seeds/* 2>/dev/null || true
