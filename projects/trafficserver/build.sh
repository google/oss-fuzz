#!/bin/bash -eu
# Copyright 2022 Google LLC
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

# don't use __cxa_atexit for coverage sanitizer
if [[ $SANITIZER = coverage ]]
then
    export CXXFLAGS="$CXXFLAGS -fno-use-cxa-atexit"
fi

# don't use unsigned-integer-overflow sanitizer {Bug in system include files}
if [[ $SANITIZER = undefined ]]
then
    export CXXFLAGS="$CXXFLAGS -fno-sanitize=unsigned-integer-overflow"
fi

mkdir -p build && cd build/
cmake -DENABLE_POSIX_CAP=OFF -DENABLE_FUZZING=ON -DYAML_BUILD_SHARED_LIBS=OFF ../.
make -j$(nproc) --ignore-errors

cp tests/fuzzing/fuzz_* $OUT/
cp -r tests/fuzzing/lib/ $OUT/
cp $SRC/trafficserver/tests/fuzzing/*.zip  $OUT/

if [[ $SANITIZER = undefined ]]
then
    rm $OUT/fuzz_http
    rm $OUT/fuzz_hpack
fi
