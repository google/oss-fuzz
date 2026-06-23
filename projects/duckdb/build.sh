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

# BUILD_JSON=1 additionally builds the json extension (read_json / json_valid /
# json_extract), which the csv_json harness exercises; parquet is built by
# default. Both static libs are then picked up by EXTENSION_LIBS below.
make relassert CRASH_ON_ASSERT=1 DISABLE_SANITIZER=1 BUILD_JSON=1
EXTENSION_LIBS=$(find ./build/relassert/extension/ -name "*.a")
THIRD_PARTY_LIBS=$(find ./build/relassert/third_party/ -name "*.a")

# Patch the csv_json harness to force-load the statically-linked json extension.
#
# The upstream harness (test/ossfuzz/csv_json_fuzz_test.cpp) exercises the json
# functions (json_valid/json_type/json_extract/read_json), but the json
# extension built via BUILD_JSON=1 is linked as STATICALLY_LINKED and is NOT
# loaded into the catalog at startup (only parquet auto-loads). LOAD/autoload
# fall back to disk/network, which are unavailable in the build & run
# environment, so the JSON cases would otherwise fail with a catalog error and
# never reach the parser. DuckDB::LoadStaticExtension<JsonExtension>() registers
# the linked extension with no disk/network access.
#
# TODO: drop this patch once the LoadStaticExtension call is merged into the
# harness upstream (duckdb/duckdb test/ossfuzz/csv_json_fuzz_test.cpp).
CSV_JSON_HARNESS=./test/ossfuzz/csv_json_fuzz_test.cpp
sed -i \
    -e 's|#include "duckdb.hpp"|#include "duckdb.hpp"\n#include "json_extension.hpp"|' \
    -e 's|duckdb::DuckDB db(nullptr);|duckdb::DuckDB db(nullptr);\n  db.LoadStaticExtension<duckdb::JsonExtension>();|' \
    "${CSV_JSON_HARNESS}"
# Fail loudly if the anchors moved upstream rather than silently building a
# harness whose JSON cases are dead.
grep -q "LoadStaticExtension<duckdb::JsonExtension>" "${CSV_JSON_HARNESS}" || {
    echo "ERROR: failed to patch json extension load into ${CSV_JSON_HARNESS}" >&2
    exit 1
}

# Build each OSS-Fuzz harness in test/ossfuzz/ against the statically-linked
# DuckDB library plus all built-in extensions. Linking ${EXTENSION_LIBS} makes
# each extension available: parquet_fuzz_test uses read_parquet/parquet_schema
# (libparquet_extension.a, auto-loaded at startup). csv_json_fuzz_test uses
# read_csv (core) plus the json functions (libjson_extension.a, force-loaded by
# the patch above), so it is also compiled with the json extension include dir.
for harness in parse_fuzz_test parquet_fuzz_test csv_json_fuzz_test; do
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE ./test/ossfuzz/${harness}.cpp \
        -o $OUT/${harness} -I./ -I./src/include -I./third_party/fmt/include -I./extension/json/include \
        -Wl,--start-group \
        ./build/relassert/src/libduckdb_static.a \
        ${EXTENSION_LIBS} ${THIRD_PARTY_LIBS} \
        -Wl,--end-group
done
