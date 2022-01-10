#!/bin/bash -eu
# Copyright 2021 Google LLC
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

# build ICU for linking statically.
cd $SRC/icu/source
./configure --disable-shared --enable-static --disable-layoutex \
  --disable-tests --disable-samples --with-data-packaging=static
make install -j$(nproc)

# Ugly ugly hack to get static linking to work for icu.
cd lib
ls *.a | xargs -n1 ar x
rm *.a
ar r libicu.a *.{ao,o}
ln -s $PWD/libicu.a /usr/lib/x86_64-linux-gnu/libicudata.a
ln -s $PWD/libicu.a /usr/lib/x86_64-linux-gnu/libicuuc.a
ln -s $PWD/libicu.a /usr/lib/x86_64-linux-gnu/libicui18n.a

# remove dynamic libraries of libunwind to force static linking
find / -name "libunwind*.so*" -exec rm {} \;

cd $SRC/tarantool

# Avoid compilation issue due to some unused variables. They are in fact
# not unused, but the compilers are complaining.
sed -i 's/total = 0;/total = 0;(void)total;/g' ./src/lib/core/crash.c
sed -i 's/n = 0;/n = 0;(void)n;/g' ./src/lib/core/sio.c

case $SANITIZER in
  address) SANITIZERS_ARGS="-DENABLE_ASAN=ON" ;;
  undefined) SANITIZERS_ARGS="-DENABLE_UB_SANITIZER=ON" ;;
  *) SANITIZERS_ARGS="" ;;
esac

: ${LD:="${CXX}"}
: ${LDFLAGS:="${CXXFLAGS}"}  # to make sure we link with sanitizer runtime

cmake_args=(
    # Specific to Tarantool
    -DENABLE_FUZZER=ON
    -DOSS_FUZZ=ON
    $SANITIZERS_ARGS

    # C compiler
    -DCMAKE_C_COMPILER="${CC}"
    -DCMAKE_C_FLAGS="${CFLAGS}"

    # C++ compiler
    -DCMAKE_CXX_COMPILER="${CXX}"
    -DCMAKE_CXX_FLAGS="${CXXFLAGS}"

    # Linker
    -DCMAKE_LINKER="${LD}"
    -DCMAKE_EXE_LINKER_FLAGS="${LDFLAGS}"
    -DCMAKE_MODULE_LINKER_FLAGS="${LDFLAGS}"
    -DCMAKE_SHARED_LINKER_FLAGS="${LDFLAGS}"
)

# Build the project and fuzzers.
[[ -e build ]] && rm -rf build
cmake "${cmake_args[@]}" -S . -B build
make -j$(nproc) VERBOSE=1 -C build fuzzers

# Archive and copy to $OUT seed corpus if the build succeeded.
for f in $(ls build/test/fuzz/*_fuzzer);
do
  name=$(basename $f);
  module=$(echo $name | sed 's/_fuzzer//')
  corpus_dir="test/static/corpus/$module"
  echo "Copying for $module";
  cp $f $OUT/
  [[ -e $corpus_dir ]] && zip -j $OUT/"$module"_fuzzer_seed_corpus.zip $corpus_dir/*
done
