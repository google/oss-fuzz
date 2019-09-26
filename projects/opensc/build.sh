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

./bootstrap
# FIXME FUZZING_LIBS="$LIB_FUZZING_ENGINE" fails with some missing C++ library, I don't know how to fix this
./configure --disable-shared --disable-pcsc --enable-ctapi --enable-fuzzing FUZZING_LIBS="$LIB_FUZZING_ENGINE"
make -j4

cp src/tests/fuzzing/fuzz_asn1_print $OUT
cp src/tests/fuzzing/fuzz_asn1_sig_value $OUT
cp src/tests/fuzzing/fuzz_pkcs15_decode $OUT
cp src/tests/fuzzing/fuzz_pkcs15_reader $OUT

#cp src/tests/fuzzing/fuzz_pkcs15_reader.options $OUT
