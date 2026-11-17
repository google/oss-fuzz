#!/bin/bash -eu

# Copyright 2020 Google LLC
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

autoreconf -f -i
./configure --enable-static --disable-man --disable-glib --disable-silent-rules
make clean

make

# the established mdbtestdata databases are the seed corpus for every target
rm -f $OUT/fuzz_mdb_seed_corpus.zip $OUT/fuzz_write_seed_corpus.zip
zip -j $OUT/fuzz_mdb_seed_corpus.zip ../mdbtestdata/data/*.mdb ../mdbtestdata/data/*.accdb
zip -j $OUT/fuzz_write_seed_corpus.zip ../mdbtestdata/data/*.mdb ../mdbtestdata/data/*.accdb

cd src/fuzz
make fuzz_mdb
cp fuzz_mdb $OUT/fuzz_mdb

# fuzz_write exercises the row-write/round-trip paths
make fuzz_write
cp fuzz_write $OUT/fuzz_write

