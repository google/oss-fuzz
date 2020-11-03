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

cp $SRC/*.dict $OUT/

CXXFLAGS="${CXXFLAGS} -O2 -fno-sanitize=integer-divide-by-zero,float-divide-by-zero"

$CXX -std=c++11 $CXXFLAGS -I. -I$SRC/exprtk \
     $SRC/exprtk_fuzzer.cpp -o $OUT/exprtk_fuzzer \
     $LIB_FUZZING_ENGINE
