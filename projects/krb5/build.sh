#!/bin/bash -eu
# Copyright 2022 Google LLC
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
pushd src/
autoreconf -f
./configure --enable-static --disable-shared CC=$CC CXX=$CXX CFLAGS="-fcommon $CFLAGS" CXXFLAGS="-fcommon $CXXFLAGS" LDFLAGS="-fcommon $CFLAGS"
make
popd

pushd fuzzing/
make

cp -r rdreq/ $OUT/.

cp Fuzz_ndr $OUT/Fuzz_ndr
cp Fuzz_pac $OUT/Fuzz_pac
cp Fuzz_chpw $OUT/Fuzz_chpw
cp Fuzz_json $OUT/Fuzz_json
cp Fuzz_profile $OUT/Fuzz_profile
cp Fuzz_marshal $OUT/Fuzz_marshal
popd

pushd $SRC/oss-fuzz-bloat/krb5/
cp Fuzz_ndr_seed_corpus.zip $OUT/Fuzz_ndr_seed_corpus.zip
cp Fuzz_pac_seed_corpus.zip $OUT/Fuzz_pac_seed_corpus.zip
cp Fuzz_chpw_seed_corpus.zip $OUT/Fuzz_chpw_seed_corpus.zip
cp Fuzz_json_seed_corpus.zip $OUT/Fuzz_json_seed_corpus.zip
cp Fuzz_profile_seed_corpus.zip $OUT/Fuzz_profile_seed_corpus.zip
cp Fuzz_marshal_seed_corpus.zip $OUT/Fuzz_marshal_seed_corpus.zip
popd
