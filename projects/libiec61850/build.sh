#!/bin/bash -eu
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

cd libiec61850
mkdir build && cd build
cmake ../
make

# Header include dirs (exclude src/vs, whose stdbool.h shim shadows the system one).
INC="$(find ../src ../hal -name '*.h' -not -path '*/vs/*' -printf '-I%h\n' | sort -u) -Iconfig -I../config"

# Build every harness in the upstream fuzz/ directory.
for src in ../fuzz/*.c; do
	fuzzer=$(basename "$src" .c)
	$CC $CFLAGS -include stdbool.h $LIB_FUZZING_ENGINE "$src" -c -o "${fuzzer}.o" $INC
	$CXX $CXXFLAGS -fuse-ld=lld $LIB_FUZZING_ENGINE "${fuzzer}.o" \
		-o "$OUT/${fuzzer}" ./src/libiec61850.a ./hal/libhal.a
	# Disable leak detection for these stateful receive/server harnesses.
	printf '[asan]\ndetect_leaks=0\n' > "$OUT/${fuzzer}.options"
done
