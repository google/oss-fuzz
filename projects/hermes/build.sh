#!/bin/bash -eu
# Copyright 2020 Google Inc.
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

# build ICU for linking statically.
cd $SRC/icu/source
./configure --disable-shared --enable-static --disable-layoutex \
  --disable-tests --disable-samples --with-data-packaging=static
make install -j$(nproc)

# Ugly ugly hack to get static linking to work for icu.
cd lib
ls *.a | xargs -n1 ar x
rm *.a
ar r libicu.a *.{ao,o}
ln -s $PWD/libicu.a /usr/lib/x86_64-linux-gnu/libicudata.a
ln -s $PWD/libicu.a /usr/lib/x86_64-linux-gnu/libicuuc.a
ln -s $PWD/libicu.a /usr/lib/x86_64-linux-gnu/libicui18n.a

if [ "${SANITIZER}" = address ]
then
    CONFIGURE_FLAGS="-DHERMES_ENABLE_ADDRESS_SANITIZER=ON"
elif [ "${SANITIZER}" = undefined ]
then
    CONFIGURE_FLAGS="-DHERMES_ENABLE_UNDEFINED_BEHAVIOR_SANITIZER=ON"
else
    CONFIGURE_FLAGS=""
fi

cmake -S "${SRC}/hermes" -B "${OUT}/build" ${CONFIGURE_FLAGS} -DHERMES_USE_STATIC_ICU=ON \
                 -DHERMES_FUZZING_FLAG=${LIB_FUZZING_ENGINE} -DHERMES_ENABLE_LIBFUZZER=ON
cmake --build "$OUT/build" --target fuzzer-jsi-entry -j 4
cp "${OUT}/build/bin/fuzzer-jsi-entry" "${OUT}"
