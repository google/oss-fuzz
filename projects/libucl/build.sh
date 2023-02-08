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

cp $SRC/ucl_add_string_fuzzer.options $OUT/

cd libucl
./autogen.sh && ./configure
make

$CC $CFLAGS -c tests/fuzzers/ucl_add_string_fuzzer.c \
  -DHAVE_CONFIG_H -I./src -I./include src/.libs/libucl.a -I./ \
  -o $OUT/ucl_add_string_fuzzer.o

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE $OUT/ucl_add_string_fuzzer.o -DHAVE_CONFIG_H -I./src -I./include src/.libs/libucl.a -I. -o $OUT/ucl_add_string_fuzzer
