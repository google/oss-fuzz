#!/bin/bash -eu
#
# Copyright 2023 Google LLC
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
sh bootstrap.sh
make -j4

for f in $SRC/*_fuzzer.cc; do
  fuzzer=$(basename "$f" _fuzzer.cc)
  $CXX $CXXFLAGS -I$SRC/fftw3 -I$SRC/fftw3/api \
    $SRC/${fuzzer}_fuzzer.cc -o $OUT/${fuzzer}_fuzzer \
    $LIB_FUZZING_ENGINE -lpthread ./.libs/libfftw3.a
done

