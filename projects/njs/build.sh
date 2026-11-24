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

# Build pcre dependency to be linked statically.
pushd $SRC/pcre2
./autogen.sh
if [ "$SANITIZER" == "introspector" ]; then
  # Disable sanitizers for introspector for pcre. We only care about njs and it's blocking the build.
  CFLAGS="" CXXFLAGS="" LIB_FUZZING_ENGINE="" ./configure
else
  CFLAGS="$CFLAGS -fno-use-cxa-atexit" CXXFLAGS="$CXXFLAGS -fno-use-cxa-atexit" ./configure
fi
make -j$(nproc) clean
make -j$(nproc) all
make install
sed -i "s/\$libS\$libR \(-lpcre2-8$\)/\$libS\$libR -Wl,-Bstatic \1 -Wl,-Bdynamic/" /usr/local/bin/pcre2-config
popd

# Build libxml2 to be linked statically, so that the xml module is built.
# njs's configure finds it with pkg-config.
pushd $SRC/libxml2
LIBXML2_CMAKE_ARGS="-DBUILD_SHARED_LIBS=OFF -DCMAKE_INSTALL_PREFIX=$SRC/libxml2-install \
    -DLIBXML2_WITH_PROGRAMS=OFF -DLIBXML2_WITH_TESTS=OFF -DLIBXML2_WITH_DEBUG=OFF"
if [ "$SANITIZER" == "introspector" ]; then
  # As for pcre2: no sanitizer flags for the dependency in introspector builds.
  CFLAGS="" CXXFLAGS="" cmake -B build $LIBXML2_CMAKE_ARGS
else
  cmake -B build $LIBXML2_CMAKE_ARGS
fi
cmake --build build -j$(nproc)
cmake --install build
popd
export PKG_CONFIG_PATH=$SRC/libxml2-install/lib/pkgconfig

# build project
./configure
make njs_fuzzer

cp ./build/njs_process_script_fuzzer $OUT/

SEED_CORPUS_PATH=$OUT/njs_process_script_fuzzer_seed_corpus
mkdir -p $SEED_CORPUS_PATH

set +x
cat src/test/njs_unit_test.c \
    | egrep -o '".*"' | awk '{print substr($0,2,length($0)-2)}' | sort | uniq \
    | while IFS= read -r line; do
      echo $line > $SEED_CORPUS_PATH/$(echo $line | sha1sum | awk '{ print $1 }');
    done

find test/ -name *.t.js \
    | while IFS= read -r testname; do
        cp $testname $SEED_CORPUS_PATH/$(echo $testname | sha1sum | awk '{ print $1 }');
      done
set -x

zip -q $SEED_CORPUS_PATH.zip $SEED_CORPUS_PATH
rm -rf $SEED_CORPUS_PATH
