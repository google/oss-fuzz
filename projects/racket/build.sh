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

# Builds the Racket CS fuzz targets. Each target boots Racket once and
# passes each input to one `fuzz-*` entry point of "safe-eval.rkt",
# which runs it in a sandbox and checks one property. The boot files
# and the compiled harness modules are embedded in each target.

FUZZ=$SRC/racket-fuzz
TARGETS="eval read print-roundtrip number regexp fasl"

# The build runs the sanitized Racket, which leaks at exit and may hit
# UBSan reports in code that the fuzzers never reach
export ASAN_OPTIONS=detect_leaks=0
export UBSAN_OPTIONS=halt_on_error=0
# Compile Scheme code with coverage counters, for the fuzzer's feedback
export PLT_CS_COVERAGE_COUNTERS=1

# build_targets <name> <targets>: links the targets against the Racket
# installed in $WORK/<name>, as $OUT/<name>_<target>_fuzzer
build_targets () {
  local name=$1 targets=$2
  local prefix=$WORK/$name
  $prefix/bin/racket $FUZZ/embed-modules.rkt $WORK/fuzz-modules.bin
  $CC -c -Ulinux -Uunix $FUZZ/embed-data.S -o $WORK/embed-data.o \
    -DPETITE_BOOT=$prefix/lib/racket/petite.boot \
    -DSCHEME_BOOT=$prefix/lib/racket/scheme.boot \
    -DRACKET_BOOT=$prefix/lib/racket/racket.boot \
    -DFUZZ_MODULES=$WORK/fuzz-modules.bin
  for t in $targets ; do
    $CC $CFLAGS -DRACKET_COVERAGE_COUNTERS -I$prefix/include/racket \
      -DFUZZ_EMBEDDED -DFUZZ_ENTRY="\"fuzz-$t\"" \
      -c $FUZZ/driver.c -o $WORK/driver-$t.o
    $CC $CFLAGS $LIB_FUZZING_ENGINE $WORK/driver-$t.o $WORK/embed-data.o \
      $WORK/build-$name/cs/c/libracketcs.a \
      -lz -lm -ldl -lpthread -lncurses -o $OUT/${name}_${t}_fuzzer
  done
}

# Two builds: the normal one ("racket_*" targets), and one configured
# with `--enable-check` ("racket_check_*" targets), where Racket's core
# layers (expander, io, regexp, thread, schemify) are compiled in safe
# mode and Chez Scheme's own code at optimize-level 2, so that a broken
# internal assumption raises an error instead of corrupting memory
build_variant () {
  local name=$1 targets=$2 ; shift 2
  mkdir -p $WORK/build-$name
  cd $WORK/build-$name
  $SRC/racket/racket/src/configure \
    --enable-cs --disable-pthread --enable-libs --prefix=$WORK/$name "$@" \
    CC="$CC" CFLAGS="$CFLAGS -DRACKET_COVERAGE_COUNTERS" LDFLAGS="$CFLAGS"
  make -j$(nproc)
  make install
  build_targets $name "$targets"
}

# the heap-check target has Chez Scheme check the whole heap after each
# input; it is slow, so it gets a longer timeout below
build_variant racket "$TARGETS heap-eval"
build_variant racket_check "$TARGETS" --enable-check

# Seed corpora from the core tests
$WORK/racket/bin/racket $FUZZ/make-corpus.rkt \
  $SRC/racket/pkgs/racket-test-core/tests/racket $WORK/corpus
for t in eval read number regexp fasl ; do
  (cd $WORK/corpus/$t && zip -q -r $OUT/racket_${t}_fuzzer_seed_corpus.zip .)
done
cp $OUT/racket_read_fuzzer_seed_corpus.zip $OUT/racket_print-roundtrip_fuzzer_seed_corpus.zip
cp $OUT/racket_eval_fuzzer_seed_corpus.zip $OUT/racket_heap-eval_fuzzer_seed_corpus.zip

for t in $TARGETS ; do
  printf '[libfuzzer]\nmax_len = 4096\ntimeout = 20\n' > $OUT/racket_${t}_fuzzer.options
  # safe-mode code is slower
  printf '[libfuzzer]\nmax_len = 4096\ntimeout = 40\n' > $OUT/racket_check_${t}_fuzzer.options
  cp $OUT/racket_${t}_fuzzer_seed_corpus.zip $OUT/racket_check_${t}_fuzzer_seed_corpus.zip
done
printf '[libfuzzer]\nmax_len = 4096\ntimeout = 60\n' > $OUT/racket_heap-eval_fuzzer.options
