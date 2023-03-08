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

# Clean up potentially persistent build directory.
[[ -e $SRC/tarantool/build ]] && rm -rf $SRC/tarantool/build

# Build ICU for linking statically.
mkdir -p $SRC/tarantool/build/icu && cd $SRC/tarantool/build/icu

[ ! -e config.status ] && LDFLAGS="-lpthread" CXXFLAGS="$CXXFLAGS -lpthread" \
  $SRC/icu/source/configure --disable-shared --enable-static --disable-layoutex \
  --disable-tests --disable-samples --with-data-packaging=static
make install -j$(nproc)

cd $SRC/tarantool

# Avoid compilation issue due to some unused variables. They are in fact
# not unused, but the compilers are complaining.
sed -i 's/total = 0;/total = 0;(void)total;/g' ./src/lib/core/crash.c
sed -i 's/n = 0;/n = 0;(void)n;/g' ./src/lib/core/sio.c
# Avoid compilation issue due to some undefined references. They are defined in
# libc++ and used by Centipede so -lc++ needs to come after centipede's lib.
if [[ $FUZZING_ENGINE == centipede ]]
then
    sed -i \
        '/$ENV{LIB_FUZZING_ENGINE}/a \ \ \ \ \ \ \ \ -lc++' \
        test/fuzz/CMakeLists.txt
fi

case $SANITIZER in
  address) SANITIZERS_ARGS="-DENABLE_ASAN=ON" ;;
  undefined) SANITIZERS_ARGS="-DENABLE_UB_SANITIZER=ON" ;;
  *) SANITIZERS_ARGS="" ;;
esac

: ${LD:="${CXX}"}
: ${LDFLAGS:="${CXXFLAGS}"}  # to make sure we link with sanitizer runtime

cmake_args=(
    # Specific to Tarantool
    -DENABLE_BACKTRACE=OFF
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

    # Dependencies
    -DENABLE_BUNDLED_LIBCURL=OFF
    -DENABLE_BUNDLED_LIBUNWIND=OFF
    -DENABLE_BUNDLED_ZSTD=OFF
)

# To deal with a host filesystem from inside of container.
git config --global --add safe.directory '*'

# Build the project and fuzzers.
[[ -e build ]] && rm -rf build
cmake "${cmake_args[@]}" -S . -B build -G Ninja
cmake --build build --target fuzzers --parallel

# Archive and copy to $OUT seed corpus if the build succeeded.
for f in $(find build/test/fuzz/ -name '*_fuzzer' -type f);
do
  name=$(basename $f);
  module=$(echo $name | sed 's/_fuzzer//')
  corpus_dir="test/static/corpus/$module"
  echo "Copying for $module";
  cp $f $OUT/
  [[ -e $corpus_dir ]] && zip -j $OUT/"$module"_fuzzer_seed_corpus.zip $corpus_dir/*
done
