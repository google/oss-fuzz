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

if [ "${SANITIZER}" = address ]
then
    CONFIGURE_FLAGS="--enable-asan"
elif [ "${SANITIZER}" = undefined ]
then
    CONFIGURE_FLAGS="--enable-ubsan"
else
    CONFIGURE_FLAGS=""
fi

./utils/build/configure.py "${OUT}/build" --build-system "Ninja" ${CONFIGURE_FLAGS} \
                           --cmake-flags="-DHERMES_USE_STATIC_ICU=ON -DHERMES_FUZZING_FLAG=${LIB_FUZZING_ENGINE} -DHERMES_ENABLE_LIBFUZZER=ON"
cmake --build "$OUT/build"  --parallel --target fuzzer-jsi-entry
cp "${OUT}/build/bin/fuzzer-jsi-entry" "${OUT}"
