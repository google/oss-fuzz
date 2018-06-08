#!/bin/bash -eu
# Copyright 2018 Google Inc.
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

./autogen.sh && ./configure --disable-doxygen --disable-manpages \
       		&& make -j$(nproc)

LIBFUZZER_SRC=$SRC/libfuzzer

### standalone stub
$CC $CFLAGS -c $LIBFUZZER_SRC/standalone/StandaloneFuzzTargetMain.c \
	-I $LIBFUZZER_SRC/standalone -o $OUT/standalone.o

for file in $SRC/*target.c; do
	b=$(basename $file _target.c)
	$CC $CFLAGS -c $file -I include/coap \
		-o $OUT/${b}_target.o
	$CXX $CXXFLAGS $OUT/${b}_target.o ./.libs/libcoap-2.a \
	-lFuzzingEngine \
	-o $OUT/${b}_fuzzer
	$CXX $CXXFLAGS $OUT/${b}_target.o $OUT/standalone.o \
		-I $LIBFUZZER_SRC/standalone ./.libs/libcoap-2.a \
		-o $OUT/${b}_standalone
	rm -f $OUT/${b}_target.o
done
rm -f $OUT/standalone.o
cp $SRC/*.dict $SRC/*.options $OUT/
