
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

cd /src/sqlite3

rm -rf fossil
mkdir fossil
cd fossil

fossil clone https://www.sqlite.org/src sqlite --user `whoami`
fossil open sqlite

mkdir bld
cd bld

export ASAN_OPTIONS=detect_leaks=0
../configure
make
make sqlite3.c

$CXX $CXXFLAGS -std=c++11 -I. \
    /src/oss-fuzz/sqlite3/sqlite3_fuzzer.cc -o /out/sqlite3_fuzzer \
    /work/libfuzzer/*.o ./sqlite3.o $LDFLAGS
