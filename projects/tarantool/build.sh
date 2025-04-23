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

# For fuzz-introspector, exclude all functions in the tests directory,
# libprotobuf-mutator and protobuf source code.
# See https://github.com/ossf/fuzz-introspector/blob/main/doc/Config.md#code-exclusion-from-the-report
export FUZZ_INTROSPECTOR_CONFIG=$SRC/fuzz_introspector_exclusion.config
cat > $FUZZ_INTROSPECTOR_CONFIG <<EOF
FILES_TO_AVOID
tarantool/build/test
tarantool/build/icu-prefix
EOF

cd $SRC/tarantool

case $SANITIZER in
  address) SANITIZERS_ARGS="-DENABLE_ASAN=ON" ;;
  undefined) SANITIZERS_ARGS="-DENABLE_UB_SANITIZER=ON" ;;
  *) SANITIZERS_ARGS="" ;;
esac

export LSAN_OPTIONS="verbosity=1:log_threads=1"

# Workaround for a LeakSanitizer crashes,
# see https://github.com/google/oss-fuzz/issues/11798.
if [ "$ARCHITECTURE" = "aarch64" ]; then
    export ASAN_OPTIONS=detect_leaks=0
fi

: ${LD:="${CXX}"}
: ${LDFLAGS:="${CXXFLAGS}"}  # to make sure we link with sanitizer runtime

cmake_args=(
    # Specific to Tarantool
    -DENABLE_BACKTRACE=OFF
    -DENABLE_FUZZER=ON
    -DOSS_FUZZ=ON
    -DLUA_USE_APICHECK=ON
    -DLUA_USE_ASSERT=ON
    -DLUAJIT_USE_SYSMALLOC=ON
    -DLUAJIT_ENABLE_GC64=ON
    $SANITIZERS_ARGS

    -DCMAKE_BUILD_TYPE=Debug

    # C compiler
    -DCMAKE_C_COMPILER="${CC}"
    -DCMAKE_C_FLAGS="${CFLAGS} -Wno-error=unused-command-line-argument"

    # C++ compiler
    -DCMAKE_CXX_COMPILER="${CXX}"
    -DCMAKE_CXX_FLAGS="${CXXFLAGS} -Wno-error=unused-command-line-argument"

    # Linker
    -DCMAKE_LINKER="${LD}"
    -DCMAKE_EXE_LINKER_FLAGS="${LDFLAGS}"
    -DCMAKE_MODULE_LINKER_FLAGS="${LDFLAGS}"
    -DCMAKE_SHARED_LINKER_FLAGS="${LDFLAGS}"

    # Dependencies
    -DENABLE_BUNDLED_ICU=ON
    -DENABLE_BUNDLED_LIBUNWIND=OFF
    -DENABLE_BUNDLED_ZSTD=OFF
)

# To deal with a host filesystem from inside of container.
git config --global --add safe.directory '*'

# Build the project and fuzzers.
[[ -e build ]] && rm -rf build
cmake "${cmake_args[@]}" -S . -B build
cmake --build build --target fuzzers --parallel --verbose

# Archive and copy to $OUT seed corpus if the build succeeded.
# Postfix `_fuzzer` is used in Tarantool, postfix `_test` is
# used in Lua C API tests [1].
#
# 1. https://github.com/ligurio/lua-c-api-tests/
cp test/static/*.dict test/static/*.options $OUT/
for f in $(find build/test/fuzz/ \( -name '*_fuzzer' -o -name '*_test' \) -type f);
do
  name=$(basename $f);
  module=$(echo $name | sed 's/_fuzzer//' | sed 's/_test//' )
  corpus_dir="test/static/corpus/$module"
  echo "Copying for $module";
  cp $f $OUT/
  if [ -e "$corpus_dir" ]; then
    zip --quiet -j $OUT/"$name"_seed_corpus.zip $corpus_dir/*
  fi
done
