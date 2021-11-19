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

pushd mpg123
if [[ "$ARCHITECTURE" == "i386" ]]; then
	./configure --enable-static --with-cpu=$ARCHITECTURE
else
	./configure --enable-static
fi
make -j$(nproc)
make install
popd

cd $SRC/lame
./configure
make -j$(nproc)

cd $SRC/LAME-fuzzers
if [[ $CXXFLAGS = *sanitize=memory* ]]
then
    export CXXFLAGS="$CXXFLAGS -DMSAN"
fi

$CXX -std=c++17 -Wall -Wextra -Werror $CXXFLAGS -I fuzzing-headers/include/ -I $SRC/lame/include/ fuzzer-encoder.cpp $LIB_FUZZING_ENGINE $SRC/lame/libmp3lame/.libs/libmp3lame.a /usr/local/lib/libmpg123.a -lm -o $OUT/fuzzer-encoder
cp fuzzer-encoder_seed_corpus.zip $OUT/
cp fuzzer-encoder.dict $OUT/
