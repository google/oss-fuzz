#!/bin/bash -eu
# Copyright 2016 Google Inc.
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

mkdir -p $WORK/open62541
cd $WORK/open62541

cmake -DCMAKE_BUILD_TYPE=Debug -DUA_ENABLE_AMALGAMATION=OFF \
      -DBUILD_SHARED_LIBS=OFF -DUA_BUILD_EXAMPLES=OFF -DUA_LOGLEVEL=400 \
      -DUA_ENABLE_DISCOVERY=ON -DUA_ENABLE_DISCOVERY_MULTICAST=ON \
      $SRC/open62541/

# for now just use one processor, otherwise amalgamation may fail
make -j1

# ------------------------------------------------------------
# Add additional definitions which are normally set with CMake
# ------------------------------------------------------------

# Definitions
CFLAGS="$CFLAGS -DUA_NO_AMALGAMATION"
# Include dirs
CFLAGS="$CFLAGS -I$WORK/open62541/src_generated -I$SRC/open62541/include -I$SRC/open62541/plugins -I$SRC/open62541/deps -I$SRC/open62541/src -I$SRC/open62541/src/server"

# ------------------------------------------------------------
# Build all the fuzzing targets in tests/fuzz
# ------------------------------------------------------------

fuzzerFiles=$(find $SRC/open62541/tests/fuzz/ -name "*.c")

for F in $fuzzerFiles; do
	fuzzerName=$(basename $F .c)
	echo "Building fuzzer $fuzzerName"

	$CC $CFLAGS -c \
		$F -o $OUT/${fuzzerName}.o

	$CXX $CXXFLAGS \
		$OUT/${fuzzerName}.o -o $OUT/${fuzzerName} \
		-lFuzzingEngine -L $WORK/open62541/bin -lopen62541

	if [ -d "$SRC/open62541/tests/fuzz/${fuzzerName}_corpus" ]; then
		zip -j $OUT/${fuzzerName}_seed_corpus.zip $SRC/open62541/tests/fuzz/${fuzzerName}_corpus/*
	fi
done

cp $SRC/open62541/tests/fuzz/*.dict $SRC/open62541/tests/fuzz/*.options $OUT/

echo "Built all fuzzer targets."
