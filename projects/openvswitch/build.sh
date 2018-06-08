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

./boot.sh && ./configure && make -j$(nproc)
$CC $CFLAGS -c -g $SRC/target-flow-extract.c -I . -I lib/ -I include/ \
		-o $SRC/target-flow-extract.o
$CXX $CXXFLAGS $SRC/target-flow-extract.o ./lib/.libs/libopenvswitch.a \
	-lz -lssl -lcrypto -latomic -lFuzzingEngine \
	-o $OUT/flow_extract_fuzzer
