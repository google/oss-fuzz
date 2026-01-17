#!/bin/bash -eu
# Copyright 2020 Google LLC
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

# For some reason the linker will complain if address sanitizer is not used
# in introspector builds.
if [ "$SANITIZER" == "introspector" ]; then
  export CFLAGS="${CFLAGS} -fsanitize=address"
  export CXXFLAGS="${CXXFLAGS} -fsanitize=address"
fi

PACKAGES="build-essential ninja-build cmake make"
if [ "$ARCHITECTURE" = "i386" ]; then
    PACKAGES="$PACKAGES zlib1g-dev:i386 libreadline-dev:i386 libunwind-dev:i386"
elif [ "$ARCHITECTURE" = "aarch64" ]; then
    PACKAGES="$PACKAGES zlib1g-dev:arm64 libreadline-dev:arm64 libunwind-dev:arm64"
else
    PACKAGES="$PACKAGES zlib1g-dev libreadline-dev libunwind-dev"
fi
apt-get update
apt-get install -y $PACKAGES

apt install -y cmake luarocks
# apt install -y liblua5.1-0 liblua5.1-0-dev lua5.1
apt install -y liblua5.4-0 liblua5.4-dev lua5.4

# For fuzz-introspector, exclude all functions in the tests directory,
# libprotobuf-mutator and protobuf source code.
# See https://github.com/ossf/fuzz-introspector/blob/main/doc/Config.md#code-exclusion-from-the-report
export FUZZ_INTROSPECTOR_CONFIG=$SRC/fuzz_introspector_exclusion.config
cat > $FUZZ_INTROSPECTOR_CONFIG <<EOF
FILES_TO_AVOID
testdir/build/tests/capi/external.protobuf_mutator
testdir/build/tests/capi/luaL_loadbuffer_proto/
EOF

cd $SRC/testdir

# Avoid compilation issue due to some undefined references. They are defined in
# libc++ and used by Centipede so -lc++ needs to come after centipede's lib.
if [[ $FUZZING_ENGINE == centipede ]]
then
    sed -i \
        '/$ENV{LIB_FUZZING_ENGINE}/a \ \ \ \ \ \ \ \ -lc++' \
        tests/capi/CMakeLists.txt
fi

# Clean up potentially persistent build directory.
[[ -e $SRC/testdir/build ]] && rm -rf $SRC/testdir/build

case $SANITIZER in
  address) SANITIZERS_ARGS="-DENABLE_ASAN=ON" ;;
  undefined) SANITIZERS_ARGS="-DENABLE_UBSAN=ON" ;;
  *) SANITIZERS_ARGS="" ;;
esac

export LSAN_OPTIONS="verbosity=1:log_threads=1"

# Workaround for a LeakSanitizer crashes,
# see https://github.com/google/oss-fuzz/issues/11798.
if [ "$ARCHITECTURE" = "aarch64" ]; then
    export ASAN_OPTIONS=detect_leaks=0
fi

export OSS_FUZZ=1

: ${LD:="${CXX}"}
: ${LDFLAGS:="${CXXFLAGS}"}  # to make sure we link with sanitizer runtime

cmake_args=(
    -DUSE_LUA=ON
    -DOSS_FUZZ=ON
    # "dynamic libraries not enabled; check your Lua installation"
    -DENABLE_LAPI_TESTS=ON
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

# To deal with a host filesystem from inside of container.
git config --global --add safe.directory '*'

# Build the project and fuzzers.
[[ -e build ]] && rm -rf build
git pull --rebase
cmake "${cmake_args[@]}" -S . -B build -G Ninja
# cmake --build build --parallel --verbose
cmake --build build --parallel --verbose --target patched-lua-master

LUALIB_PATH="$SRC/testdir/build/lua-master/source/"
$CC $CFLAGS -I$LUALIB_PATH -c $SRC/fuzz_lua.c -o fuzz_lua.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_lua.o -o $OUT/fuzz_lua $LUALIB_PATH/liblua.a

# If the dict filename is the same as your target binary name
# (i.e. `%fuzz_target%.dict`), it will be automatically used.
# If the name is different (e.g. because it is shared by several
# targets), specify this in .options file.
# cp corpus_dir/*.dict corpus_dir/*.options $OUT/

# Archive and copy to $OUT seed corpus if the build succeeded.
for f in $(find build/tests/ -name '*_test' -type f);
do
  name=$(basename $f);
  module=$(echo $name | sed 's/_test//')
  corpus_dir="corpus_dir/$module"
  echo "Copying for $module";
  cp $f $OUT/
  [[ -e $corpus_dir ]] && find "$corpus_dir" -mindepth 1 -maxdepth 1 | zip -@ -j $OUT/"$name"_seed_corpus.zip
done

# Finish execution if libFuzzer is not used, because luzer
# is libFuzzer-based.
if [[ "$FUZZING_ENGINE" != libfuzzer ]]; then
  return
fi

# Lua 5.5 is not released, so we should setup luarocks for a Lua
# version built by tests.
# http://lua-users.org/wiki/LuaRocksConfig
# https://github.com/luarocks/luarocks/blob/main/docs/config_file_format.md
# https://github.com/luarocks/luarocks/pull/1844
# The command below requires a latest version of luarocks (Ubuntu 24.04).
# See also luarocks and lua wrappers.
# luarocks config --tree=lua_modules --local variables.LUA_INCDIR build/lua-master/source/
# luarocks config --tree=lua_modules --local variables.LUA_LIBDIR build/lua-master/source/
# luarocks config --tree=lua_modules --local variables.LUA_LIBDIR build/lua-master/source/
# luarocks config lua_dir build/lua-master/source/
# luarocks config lua_interpreter
# luarocks install --lua-version 5.5 --tree=lua_modules $SRC/luzer-scm-1.rockspec

luarocks install --lua-version 5.4 --tree=lua_modules --server=https://luarocks.org/dev luzer

LUA_RUNTIME_NAME=lua

for fuzzer in $(find $SRC -name '*_test.lua'); do
  $SRC/compile_lua_fuzzer $LUA_RUNTIME_NAME $(basename $fuzzer)
  cp $fuzzer "$OUT/"
done

cp ./build/lua-master/source/lua "$OUT/$LUA_RUNTIME_NAME"
cp -R lua_modules "$OUT/"
