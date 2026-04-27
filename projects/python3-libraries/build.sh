#!/bin/bash -eu
# Copyright 2019 Google Inc.
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

# Some fuzz tests in fuzzer.c use CPython internal API. Carried over from
# the former cpython3 project.
CFLAGS="${CFLAGS} -I${SRC}/cpython/Include/internal/"

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

export CPYTHON_INSTALL_PATH=$SRC/cpython-install
rm -rf $CPYTHON_INSTALL_PATH
mkdir $CPYTHON_INSTALL_PATH

cd $SRC/cpython
cp $SRC/library-fuzzers/python_coverage.h Python/

# Patch the interpreter to record code coverage
sed -i '1 s/^.*$/#include "python_coverage.h"/g' Python/ceval.c
sed -i 's/case TARGET\(.*\): {/\0\nfuzzer_record_code_coverage(f->f_code, f->f_lasti);/g' Python/ceval.c

./configure "${FLAGS[@]:-}" --prefix=$CPYTHON_INSTALL_PATH
make -j$(nproc)
make install

cp -R $CPYTHON_INSTALL_PATH $OUT/
$OUT/cpython-install/bin/python3 -m pip install hypothesis

cd $SRC/library-fuzzers
make

# ------------------------- Python harness fuzzers ----------------------------#
while read -r name fuzzer; do
  cp $SRC/library-fuzzers/fuzzer-$name $OUT/
  cp $SRC/library-fuzzers/$fuzzer $OUT/
  if [ -d "corp-$name" ]; then
    zip -j "$OUT/fuzzer-${name}_seed_corpus.zip" corp-$name/*
  fi
  if [ -f "fuzzer-${name}.dict" ]; then
    cp "fuzzer-${name}.dict" "$OUT/fuzzer-${name}.dict"
  fi
done < $SRC/library-fuzzers/fuzz_targets.txt

cp $SRC/library-fuzzers/fuzzeddataprovider.py $OUT/

# Use CPython source code as seed corpus
cp $SRC/library-fuzzers/dictionaries/fuzz_pycompile.dict $OUT/fuzzer-ast.dict
mkdir corp-ast/
find $SRC/cpython -type f -name '*.py' -size -4097c -exec cp {} corp-ast/ \;
zip -j $OUT/fuzzer-ast_seed_corpus.zip corp-ast/*

# ---------------------------- C harness fuzzers ------------------------------#
while read -r fuzz_test; do
  cp $SRC/library-fuzzers/$fuzz_test $OUT/

  # Zip up and copy any seed corpus
  if [ -d "$SRC/library-fuzzers/${fuzz_test}_corpus" ]; then
    zip -j "$OUT/${fuzz_test}_seed_corpus.zip" $SRC/library-fuzzers/${fuzz_test}_corpus/*
  fi
  # Copy over the dictionary for this test
  if [ -e "$SRC/library-fuzzers/dictionaries/${fuzz_test}.dict" ]; then
    cp "$SRC/library-fuzzers/dictionaries/${fuzz_test}.dict" "$OUT/${fuzz_test}.dict"
  fi
done < $SRC/library-fuzzers/fuzz_tests.txt

# A little bit hacky but we have to copy $OUT/include to
# $OUT/$OUT/include as the coverage build needs all source
# files used in execution and expects it to be there.
#   See projects/tensorflow/build.sh for prior art
if [ "$SANITIZER" = "coverage" ]
then
  mkdir -p $OUT/$OUT
  cp -r $OUT/cpython-install/include $OUT/$OUT/
fi
