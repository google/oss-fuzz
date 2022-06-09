#!/bin/bash -eu
# Copyright 2018 Google Inc.
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

pushd $SRC/ogg
./autogen.sh
./configure --prefix="$WORK" --enable-static --disable-shared --disable-crc
make clean
make -j$(nproc)
make install
popd

./autogen.sh
export CFLAGS="$CFLAGS -DDISABLE_NOTIFICATIONS -DDISABLE_WARNINGS"
# Build fixed-point fuzzer
PKG_CONFIG_PATH="$WORK"/lib/pkgconfig ./configure --prefix="$WORK" --enable-static --disable-shared --enable-fixed
make -j$(nproc)
make install
$CXX $CXXFLAGS contrib/oss-fuzz/speexdec_fuzzer.cc -o $OUT/speex_decode_fuzzer_fixed -L"$WORK/lib" -I"$WORK/include" $LIB_FUZZING_ENGINE -lspeex -logg
# Build floating-point fuzzer
PKG_CONFIG_PATH="$WORK"/lib/pkgconfig ./configure --prefix="$WORK" --enable-static --disable-shared
make -j$(nproc)
make install
$CXX $CXXFLAGS contrib/oss-fuzz/speexdec_fuzzer.cc -o $OUT/speex_decode_fuzzer_float -L"$WORK/lib" -I"$WORK/include" $LIB_FUZZING_ENGINE -lspeex -logg

# build samples and prepare corpus
cd src/
./generate-samples.sh
zip -j0r ${OUT}/speex_decode_fuzzer_fixed_seed_corpus.zip ./samples/
cp ${OUT}/speex_decode_fuzzer_fixed_seed_corpus.zip ${OUT}/speex_decode_fuzzer_float_seed_corpus.zip
cd ..
