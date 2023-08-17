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

# Use ~ as sed delimiters instead of the usual "/" because C(XX)FLAGS may
# contain paths with slashes.
sed "s~CFLAGS=~CFLAGS+=~g" -i $SRC/lua/makefile
sed "s~MYLDFLAGS=~MYLDFLAGS=${CFLAGS} ~g" -i $SRC/lua/makefile
sed "s|CC= gcc|CC= ${CC}|g" -i $SRC/lua/makefile

cd $SRC/lua
make
cp ../fuzz_lua.c .
$CC $CFLAGS -c fuzz_lua.c -o fuzz_lua.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_lua.o -o $OUT/fuzz_lua ./liblua.a

cd $SRC/testdir

# Avoid compilation issue due to some undefined references. They are defined in
# libc++ and used by Centipede so -lc++ needs to come after centipede's lib.
if [[ $FUZZING_ENGINE == centipede ]]
then
    sed -i \
        '/$ENV{LIB_FUZZING_ENGINE}/a \ \ \ \ \ \ \ \ -lc++' \
        tests/CMakeLists.txt
fi

# Clean up potentially persistent build directory.
[[ -e $SRC/testdir/build ]] && rm -rf $SRC/testdir/build

case $SANITIZER in
  address) SANITIZERS_ARGS="-DENABLE_ASAN=ON" ;;
  undefined) SANITIZERS_ARGS="-DENABLE_UBSAN=ON" ;;
  *) SANITIZERS_ARGS="" ;;
esac

: ${LD:="${CXX}"}
: ${LDFLAGS:="${CXXFLAGS}"}  # to make sure we link with sanitizer runtime

cmake_args=(
    -DUSE_LUA=ON
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

# To deal with a host filesystem from inside of container.
git config --global --add safe.directory '*'

# Build the project and fuzzers.
[[ -e build ]] && rm -rf build
cmake "${cmake_args[@]}" -S . -B build -G Ninja
cmake --build build --parallel

cp corpus_dir/*.options $OUT/

# Archive and copy to $OUT seed corpus if the build succeeded.
for f in $(find build/tests/ -name '*_test' -type f);
do
  name=$(basename $f);
  module=$(echo $name | sed 's/_test//')
  corpus_dir="corpus_dir/$module"
  echo "Copying for $module";
  cp $f $OUT/
  dict_path="corpus_dir/$module.dict"
  if [ -e "$dict_path" ]; then
    cp $dict_path "$OUT/$name.dict"
  fi
  [[ -e $corpus_dir ]] && find "$corpus_dir" -mindepth 1 -maxdepth 1 | zip -@ -j $OUT/"$name"_seed_corpus.zip
done
