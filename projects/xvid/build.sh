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

cd $SRC/trunk/xvidcore/build/generic/
./bootstrap.sh
mkdir $SRC/xvidcore-install/
if [[ $CFLAGS = *sanitize=memory* ]]
then
    ./configure --prefix=$SRC/xvidcore-install/ --disable-assembly
else
    if [[ $CFLAGS = *-m32* ]]
    then
        LDFLAGS="-m32" ./configure --prefix=$SRC/xvidcore-install/ --disable-assembly
    else
        ./configure --prefix=$SRC/xvidcore-install/
    fi
fi
make -j $(nproc)
make install

find $SRC/xvidcore-install/

$CXX $CXXFLAGS -I $SRC/xvidcore-install/include $SRC/oss-fuzz-fuzzers/xvid/fuzzer.cpp $SRC/xvidcore-install/lib/libxvidcore.a $LIB_FUZZING_ENGINE -o $OUT/fuzzer-decoder
