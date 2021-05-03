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

# Temporary workaround for https://github.com/google/oss-fuzz/issues/5697
wget https://github.com/bitcoin/bitcoin/commit/0be1cb158899374722961b844f9f4b0dc5f8558b.patch
( patch -p1 < ./*.patch ) || true

# Build dependencies
# This will also force static builds
if [ "$ARCHITECTURE" = "i386" ]; then
  export BUILD_TRIPLET="i686-pc-linux-gnu"
else
  export BUILD_TRIPLET="x86_64-pc-linux-gnu"
fi
(
  cd depends
  make HOST=$BUILD_TRIPLET DEBUG=1 NO_QT=1 NO_WALLET=1 NO_ZMQ=1 NO_UPNP=1 NO_NATPMP=1 -j$(nproc)
)

# Build the fuzz targets

./autogen.sh

# Limit to one target as temporary workaround for https://github.com/google/oss-fuzz/pull/5699#issuecomment-831030305
export ONLY_ONE_TARGET="process_messages"
sed -i "s|std::getenv(\"FUZZ\")|\"$ONLY_ONE_TARGET\"|g" "./src/test/fuzz/fuzz.cpp"

# OSS-Fuzz will provide CC, CXX, etc. So only set:
# * --enable-fuzz, see https://github.com/bitcoin/bitcoin/blob/master/doc/fuzzing.md
# * CONFIG_SITE, see https://github.com/bitcoin/bitcoin/blob/master/depends/README.md
CONFIG_SITE="$PWD/depends/$BUILD_TRIPLET/share/config.site" ./configure --enable-fuzz --with-sanitizers=fuzzer

make -j$(nproc)

mv ./src/test/fuzz/fuzz $OUT/$ONLY_ONE_TARGET

(
  cd assets/fuzz_seed_corpus
  for folder in ./${ONLY_ONE_TARGET}*; do
    zip --recurse-paths --quiet --junk-paths "$OUT/${folder}_seed_corpus.zip" "${folder}"
  done
)
