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

bash $SRC/build_cryptofuzz.sh

cd $SRC/bitcoin-core/

# Build dependencies
# This will also force static builds
if [ "$ARCHITECTURE" = "i386" ]; then
  export BUILD_TRIPLET="i686-pc-linux-gnu"
  # Temporary workaround for:
  #   CXXLD    test/fuzz/fuzz
  # test/fuzz/test_fuzz_fuzz-multiplication_overflow.o: In function `void (anonymous namespace)::TestMultiplicationOverflow<long long>(FuzzedDataProvider&)':
  # /src/bitcoin-core/src/test/fuzz/multiplication_overflow.cpp:30: undefined reference to `__mulodi4'
  # clang-12: error: linker command failed with exit code 1 (use -v to see invocation)
  # Makefile:5495: recipe for target 'test/fuzz/fuzz' failed
  sed -i 's|defined(HAVE_BUILTIN_MUL_OVERFLOW)|defined(IGNORE_BUILTIN_MUL_OVERFLOW)|g' "./src/test/fuzz/multiplication_overflow.cpp"
else
  export BUILD_TRIPLET="x86_64-pc-linux-gnu"
fi
(
  cd depends
  sed -i --regexp-extended '/.*rm -rf .*extract_dir.*/d' ./funcs.mk  # Keep extracted source
  make HOST=$BUILD_TRIPLET DEBUG=1 NO_QT=1 NO_WALLET=1 NO_ZMQ=1 NO_UPNP=1 NO_NATPMP=1 boost_cxxflags="-std=c++17 -fvisibility=hidden -fPIC ${CXXFLAGS}" libevent_cflags="${CFLAGS}" -j$(nproc)
)

# Build the fuzz targets

sed -i "s|PROVIDE_FUZZ_MAIN_FUNCTION|NEVER_PROVIDE_MAIN_FOR_OSS_FUZZ|g" "./configure.ac"
./autogen.sh

# OSS-Fuzz will provide CC, CXX, etc. So only set:
# * --enable-fuzz, see https://github.com/bitcoin/bitcoin/blob/master/doc/fuzzing.md
# * CONFIG_SITE, see https://github.com/bitcoin/bitcoin/blob/master/depends/README.md
CONFIG_SITE="$PWD/depends/$BUILD_TRIPLET/share/config.site" ./configure --enable-fuzz SANITIZER_LDFLAGS="$LIB_FUZZING_ENGINE"

make -j$(nproc)

WRITE_ALL_FUZZ_TARGETS_AND_ABORT="/tmp/a" "./src/test/fuzz/fuzz" || true
readarray FUZZ_TARGETS < "/tmp/a"
if [ -n "${OSS_FUZZ_CI-}" ]; then
  # When running in CI, check the first targets only to save time and disk space
  FUZZ_TARGETS=( ${FUZZ_TARGETS[@]:0:2} )
fi

# Compile the fuzz executable again with a "magic string" as the name of the fuzz target
export MAGIC_STR="b5813eee2abc9d3358151f298b75a72264ffa119d2f71ae7fefa15c4b70b4bc5b38e87e3107a730f25891ea428b2b4fabe7a84f5bfa73c79e0479e085e4ff157"
sed -i "s|std::getenv(\"FUZZ\")|\"$MAGIC_STR\"|g" "./src/test/fuzz/fuzz.cpp"
make -j$(nproc)

# Replace the magic string with the actual name of each fuzz target
for fuzz_target in ${FUZZ_TARGETS[@]}; do
  python3 -c "c_str_target=b\"${fuzz_target}\x00\";c_str_magic=b\"$MAGIC_STR\";c=open('./src/test/fuzz/fuzz','rb').read();c=c.replace(c_str_magic, c_str_target+c_str_magic[len(c_str_target):]);open(\"$OUT/$fuzz_target\",'wb').write(c)"
  chmod +x "$OUT/$fuzz_target"
  (
    cd assets/fuzz_seed_corpus
    zip --recurse-paths --quiet --junk-paths "$OUT/${fuzz_target}_seed_corpus.zip" "${fuzz_target}"
  )
done