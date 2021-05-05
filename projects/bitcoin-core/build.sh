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
  make HOST=$BUILD_TRIPLET DEBUG=1 NO_QT=1 NO_WALLET=1 NO_ZMQ=1 NO_UPNP=1 NO_NATPMP=1 boost_cxxflags="-std=c++17 -fvisibility=hidden -fPIC ${CXXFLAGS}" libevent_cflags="${CFLAGS}" -j$(nproc)
)

# Build the fuzz targets

./autogen.sh

# OSS-Fuzz will provide CC, CXX, etc. So only set:
# * --enable-fuzz, see https://github.com/bitcoin/bitcoin/blob/master/doc/fuzzing.md
# * CONFIG_SITE, see https://github.com/bitcoin/bitcoin/blob/master/depends/README.md
if [ "$FUZZING_ENGINE" = "libfuzzer" ]; then
  CONFIG_SITE="$PWD/depends/$BUILD_TRIPLET/share/config.site" ./configure --enable-fuzz --with-sanitizers=fuzzer
else
  sed -i "s|PROVIDE_FUZZ_MAIN_FUNCTION|NEVER_PROVIDE_MAIN_FOR_OSS_FUZZ|g" "./src/test/fuzz/fuzz.cpp"
  CONFIG_SITE="$PWD/depends/$BUILD_TRIPLET/share/config.site" ./configure --enable-fuzz SANITIZER_LDFLAGS="$LIB_FUZZING_ENGINE"
fi

make -j$(nproc)

# Limit to a few targets as temporary workaround for https://github.com/google/oss-fuzz/pull/5699#issuecomment-831030305
FUZZ_TARGETS=( 'process_messages' 'asmap' )
for fuzz_target in ${FUZZ_TARGETS[@]}; do
  git checkout -- "./src/test/fuzz/fuzz.cpp"
  sed -i "s|std::getenv(\"FUZZ\")|\"$fuzz_target\"|g" "./src/test/fuzz/fuzz.cpp"
  sed -i "s|PROVIDE_FUZZ_MAIN_FUNCTION|NEVER_PROVIDE_MAIN_FOR_OSS_FUZZ|g" "./src/test/fuzz/fuzz.cpp"
  make -j$(nproc)
  mv ./src/test/fuzz/fuzz $OUT/$fuzz_target
  (
    cd assets/fuzz_seed_corpus
    zip --recurse-paths --quiet --junk-paths "$OUT/${fuzz_target}_seed_corpus.zip" "${fuzz_target}"
  )
done
