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

# build project
mkdir build
cd build
cmake -DEVENT__DISABLE_MBEDTLS=ON \
      -DEVENT__DISABLE_OPENSSL=ON \
      -DEVENT__LIBRARY_TYPE=STATIC \
      -DEVENT__DISABLE_TESTS=ON \
      -DEVENT__DISABLE_SAMPLES=ON \
      ../
make -j$(nproc)
make install

# build fuzzer
for fuzzers in $(find $SRC -name '*_fuzzer.cc'); do
  fuzz_basename=$(basename -s .cc $fuzzers)
  $CXX $CXXFLAGS -std=c++11 -I../ -Iinclude \
      $fuzzers $LIB_FUZZING_ENGINE ./lib/libevent.a ./lib/libevent_core.a  \
      ./lib/libevent_pthreads.a ./lib/libevent_extra.a \
      -o $OUT/$fuzz_basename
done

if [[ "$FUZZING_ENGINE" == "honggfuzz" ]]
then
  fuzz_basename=$(basename -s .cc $fuzzers)
  $CC $CFLAGS $LIB_HFND "$HFND_CFLAGS" -Iinclude \
      $SRC/fuzz_request_cb.c $LIB_FUZZING_ENGINE ./lib/libevent.a ./lib/libevent_core.a  \
      ./lib/libevent_pthreads.a ./lib/libevent_extra.a \
      -o $OUT/fuzz_request
fi

# The dictionary is not compatible with AFL
if [ "$FUZZING_ENGINE" != 'afl' ]; then
  cp $SRC/fuzzing/dictionaries/http.dict $OUT/http_fuzzer.dict
fi
