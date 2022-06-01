#!/bin/bash
# Copyright 2022 Google LLC
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

# Ignore memory leaks from python scripts invoked in the build
export ASAN_OPTIONS="detect_leaks=0"
export MSAN_OPTIONS="halt_on_error=0:exitcode=0:report_umrs=0"

# Remove -pthread from CFLAGS, this trips up ./configure
# which thinks pthreads are available without any CLI flags
CFLAGS=${CFLAGS//"-pthread"/}

# Ensure assert statements are enabled. It may help identify problems
# earlier if those fire.
CFLAGS="${CFLAGS} -UNDEBUG"

FLAGS=()
case $SANITIZER in
  address)
    FLAGS+=("--with-address-sanitizer")
    ;;
  memory)
    FLAGS+=("--with-memory-sanitizer")
    # installing ensurepip takes a while with MSAN instrumentation, so
    # we disable it here
    FLAGS+=("--without-ensurepip")
    # -msan-keep-going is needed to allow MSAN's halt_on_error to function
    FLAGS+=("CFLAGS=-mllvm -msan-keep-going=1")
    ;;
  undefined)
    FLAGS+=("--with-undefined-behavior-sanitizer")
    ;;
esac
./configure "${FLAGS[@]:-}" --prefix $OUT

# We use altinstall to avoid having the Makefile create symlinks
make -j$(nproc) altinstall

FUZZ_DIR=Modules/_xxtestfuzz
for fuzz_test in $(cat $FUZZ_DIR/fuzz_tests.txt)
do
  # Build (but don't link) the fuzzing stub with a C compiler
  $CC $CFLAGS $($OUT/bin/python*-config --cflags) $FUZZ_DIR/fuzzer.c \
    -D _Py_FUZZ_ONE -D _Py_FUZZ_$fuzz_test -c -Wno-unused-function \
    -o $WORK/$fuzz_test.o
  # Link with C++ compiler to appease libfuzzer
  $CXX $CXXFLAGS -rdynamic $WORK/$fuzz_test.o -o $OUT/$fuzz_test \
    $LIB_FUZZING_ENGINE $($OUT/bin/python*-config --ldflags --embed)

  # Zip up and copy any seed corpus
  if [ -d "${FUZZ_DIR}/${fuzz_test}_corpus" ]; then
    zip -j "${OUT}/${fuzz_test}_seed_corpus.zip" ${FUZZ_DIR}/${fuzz_test}_corpus/*
  fi
  # Copy over the dictionary for this test
  if [ -e "${FUZZ_DIR}/dictionaries/${fuzz_test}.dict" ]; then
    cp "${FUZZ_DIR}/dictionaries/${fuzz_test}.dict" "$OUT/${fuzz_test}.dict"
  fi
done

# A little bit hacky but we have to copy $OUT/include to
# $OUT/$OUT/include as the coverage build needs all source
# files used in execution and expects it to be there.
#   See projects/tensorflow/build.sh for prior art
if [ "$SANITIZER" = "coverage" ]
then
  mkdir -p $OUT/$OUT
  cp -r $OUT/include $OUT/$OUT/
fi
