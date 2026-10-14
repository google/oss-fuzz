#!/bin/bash -eu
# Copyright 2025 Google Inc.
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

# Build libogg
cd $SRC/libogg
./autogen.sh
./configure --disable-shared --prefix=$WORK
make -j$(nproc)
make install

# Build fuzz targets
for fuzzer in ogg_sync_fuzzer ogg_pack_fuzzer; do
    $CC $CFLAGS \
        -I$WORK/include \
        -c $SRC/${fuzzer}.c -o ${fuzzer}.o
    $CXX $CXXFLAGS \
        ${fuzzer}.o \
        -o $OUT/${fuzzer} \
        $LIB_FUZZING_ENGINE \
        $WORK/lib/libogg.a
done

# Seed corpus: generate minimal valid Ogg pages as seeds
# Use a simple empty Ogg page header as the base seed
mkdir -p /tmp/ogg_seeds
# Minimal Ogg capture pattern (OggS magic + zeroed header)
printf '\x4f\x67\x67\x53\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
    > /tmp/ogg_seeds/minimal_ogg_page.ogg
zip -j $OUT/ogg_sync_fuzzer_seed_corpus.zip /tmp/ogg_seeds/*.ogg
zip -j $OUT/ogg_pack_fuzzer_seed_corpus.zip /tmp/ogg_seeds/*.ogg
