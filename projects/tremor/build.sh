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

pushd $SRC/ogg
./autogen.sh
./configure --prefix="$WORK" --enable-static --disable-shared --disable-crc
make clean
make -j$(nproc)
make install
popd

./autogen.sh --prefix="$WORK" --enable-static --disable-shared
make clean
make -j$(nproc)
make install

$CXX $CXXFLAGS decode_fuzzer.cc -o $OUT/decode_fuzzer -L"$WORK/lib" -I"$WORK/include" $LIB_FUZZING_ENGINE -lvorbisidec -logg
