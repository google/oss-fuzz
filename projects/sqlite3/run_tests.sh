#!/bin/bash -eu
# Copyright 2025 Google LLC.
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

export ASAN_OPTIONS=detect_leaks=0
cd $SRC/sqlite3/bld

# The above fails in the container.
# Ideally we should have "make tests". However, there are issues in this
# that are unresolved. It needs a non-root user in the conatiner, which is
# fine, but even after adjusting that the tests are not succeeding.
make test || true


# Run the actual tests that work within the container.
/usr/bin/tclsh8.6 /src/sqlite3/tool/srctree-check.tcl
./fuzzcheck /src/sqlite3/test/fuzzdata1.db /src/sqlite3/test/fuzzdata2.db /src/sqlite3/test/fuzzdata3.db /src/sqlite3/test/fuzzdata4.db /src/sqlite3/test/fuzzdata5.db /src/sqlite3/test/fuzzdata6.db /src/sqlite3/test/fuzzdata7.db /src/sqlite3/test/fuzzdata8.db
./sessionfuzz run /src/sqlite3/test/sessionfuzz-data1.db
./srcck1 sqlite3.c 
