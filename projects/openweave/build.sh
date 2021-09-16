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

function copy_lib
    {
    local fuzzer_path=$1
    local lib=$2
    cp $(ldd ${fuzzer_path} | grep "${lib}" | awk '{ print $3 }') ${OUT}/lib || true
    }

mkdir -p $OUT/lib

if [ "$SANITIZER" = "coverage" ]
then
    # so that we do not get openssl
    export CXXFLAGS="$CXXFLAGS -fsanitize=fuzzer-no-link,address"
    export CFLAGS="$CFLAGS -fsanitize=fuzzer-no-link,address"
fi

sed -i 's/RAND_bytes/RAND2_bytes/g' ./src/test-apps/fuzz/FuzzPASEResponderStep1.cpp
sed -i 's/RAND_bytes/RAND2_bytes/g' ./src/test-apps/fuzz/FuzzPASEResponderStep2.cpp
sed -i 's/RAND_bytes/RAND2_bytes/g' ./src/test-apps/fuzz/FuzzPASEInitiatorStep1.cpp
sed -i 's/RAND_bytes/RAND2_bytes/g' ./src/test-apps/fuzz/FuzzPASEInitiatorStep2.cpp
sed -i 's/RAND_bytes/RAND2_bytes/g' ./src/test-apps/fuzz/FuzzPASEKeyConfirm.cpp

# build project
./bootstrap
# java fails with Source option 6 is no longer supported. Use 7 or later.
./configure --disable-java --enable-fuzzing --disable-shared --without-bluez
make -j$(nproc)

for fuzzname in FuzzPASEInitiatorStep2 FuzzPASEResponderStep2 FuzzCertificateConversion FuzzPASEKeyConfirm; do
    fuzzpath=/src/openweave-core/src/test-apps/fuzz/${fuzzname}
    patchelf --set-rpath '$ORIGIN/lib' ${fuzzpath}
    copy_lib ${fuzzpath} libglib
    copy_lib ${fuzzpath} libdbus
    cp ${fuzzpath} $OUT/
done

# build corpus
ls $SRC/openweave-core/src/test-apps/fuzz/corpus/ | while read f; do
    zip -j $OUT/${f}_seed_corpus.zip $SRC/openweave-core/src/test-apps/fuzz/corpus/${f}/*;
done

cd $OUT/
ls *_seed_corpus.zip | grep PASE | while read c; do
    cp $c Fuzz$c;
done

