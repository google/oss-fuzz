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

make relassert CRASH_ON_ASSERT=1 DISABLE_SANITIZER=1
EXTENSION_LIBS=$(find ./build/relassert/extension/ -name "*.a")
THIRD_PARTY_LIBS=$(find ./build/relassert/third_party/ -name "*.a")

# Build each OSS-Fuzz harness in test/ossfuzz/ against the statically-linked
# DuckDB library plus all built-in extensions (parquet is built by default and
# its static lib is picked up by EXTENSION_LIBS above). The parquet harness
# (parquet_fuzz_test) needs the parquet extension's read_parquet/parquet_schema
# table functions, which are registered when libparquet_extension.a is linked.
for harness in parse_fuzz_test parquet_fuzz_test; do
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE ./test/ossfuzz/${harness}.cpp \
        -o $OUT/${harness} -I./ -I./src/include -I./third_party/fmt/include \
        -Wl,--start-group \
        ./build/relassert/src/libduckdb_static.a \
        ${EXTENSION_LIBS} ${THIRD_PARTY_LIBS} \
        -Wl,--end-group
done
