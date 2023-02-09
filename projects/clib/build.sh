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

cd clib
make -j$(nproc)

sed 's/int main(int argc/int main2(int argc/g' -i ./src/clib-search.c
sed 's/int main(int argc/int main2(int argc/g' -i ./src/clib-configure.c

find . -name "*.o" -exec ar rcs fuzz_lib.a {} \;

$CC $CFLAGS -Wno-unused-function -U__STRICT_ANSI__  \
	-DHAVE_PTHREADS=1 -pthread \
	-c src/common/clib-cache.c src/clib-configure.c \
        src/common/clib-settings.c src/common/clib-package.c \
        test/fuzzing/fuzz_manifest.c -I./asprintf -I./deps/ \
	-I./deps/asprintf

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_manifest.o \
	-o $OUT/fuzz_manifest  clib-cache.o clib-configure.o clib-settings.o clib-package.o \
	-I./deps/asprintf -I./deps -I./asprintf \
	fuzz_lib.a -L/usr/lib/x86_64-linux-gnu -lcurl

echo "[libfuzzer]" > $OUT/fuzz_manifest.options
echo "detect_leaks=0" >> $OUT/fuzz_manifest.options
