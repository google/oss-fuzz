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

# build zlib
pushd "$SRC/zlib"
./configure --static --prefix="$WORK"
make -j$(nproc) CFLAGS="$CFLAGS -fPIC"
make install
popd
export ZLIB_PATH=$WORK

# Enable a timeout for lockfiles rather than exit immediately. This is to
# overcome in case multiple processes try to lock a file around the same
# time. 
sed -i 's/hold_lock_file_for_update_timeout(lk, path, flags, 0);/hold_lock_file_for_update_timeout(lk, path, flags, 5000);/g' lockfile.h

# build fuzzers
make -j$(nproc) CC=$CC CXX=$CXX CFLAGS="$CFLAGS" \
  FUZZ_CXXFLAGS="$CXXFLAGS -Wl,--allow-multiple-definition" \
  LIB_FUZZING_ENGINE="common-main.o $LIB_FUZZING_ENGINE" fuzz-all

FUZZERS=""
# FUZZERS="$FUZZERS fuzz-cmd-apply-check"
FUZZERS="$FUZZERS fuzz-cmd-bundle-verify"
FUZZERS="$FUZZERS fuzz-cmd-diff"
# FUZZERS="$FUZZERS fuzz-cmd-status"
# FUZZERS="$FUZZERS fuzz-cmd-tag-create"
# FUZZERS="$FUZZERS fuzz-cmd-unpack-objects"
# FUZZERS="$FUZZERS fuzz-cmd-version"
# FUZZERS="$FUZZERS fuzz-command"
FUZZERS="$FUZZERS fuzz-commit-graph"
FUZZERS="$FUZZERS fuzz-config"
FUZZERS="$FUZZERS fuzz-credential-from-url-gently"
FUZZERS="$FUZZERS fuzz-date"
FUZZERS="$FUZZERS fuzz-pack-headers"
FUZZERS="$FUZZERS fuzz-pack-idx"
FUZZERS="$FUZZERS fuzz-parse-attr-line"
FUZZERS="$FUZZERS fuzz-url-decode-mem"
FUZZERS="$FUZZERS fuzz-url-end-with-slash"

# copy fuzzers
for fuzzer in $FUZZERS ; do
  cp oss-fuzz/$fuzzer $OUT
done

# build commit-graph corpus
ASAN_OPTIONS=detect_leaks=0 ./git commit-graph write
zip -j $OUT/fuzz-commit-graph_seed_corpus .git/objects/info/commit-graph

# Git's own packfiles are too big for effective fuzzing
# build corpora from a new repository
mkdir mock-repo
pushd mock-repo
../git init
echo "abc" > TEMP_1
../git add .
../git config user.email "you@example.com"
../git config user.name "Your Name"
../git commit -m "initial commit"
../git repack
zip -j $OUT/fuzz-pack-idx_seed_corpus.zip .git/objects/pack/*.idx
zip -j $OUT/fuzz-cmd-unpack-objects_seed_corpus .git/objects/pack/*.pack
for packfile in .git/objects/pack/*.pack ; do
  dd ibs=1 skip=12 if=$packfile of=$packfile.trimmed
done
zip -j $OUT/fuzz-pack-headers_seed_corpus.zip .git/objects/pack/*.pack.trimmed
ASAN_OPTIONS=detect_leaks=0 ../git bundle create test.bundle master
zip -j $OUT/fuzz-cmd-bundle-verify_seed_corpus test.bundle
echo "adc\nrb\n" > TEMP_1
../git diff > test.patch
zip -j $OUT/fuzz-cmd-apply-check_seed_corpus test.patch
popd
rm -rf mock-repo

for fuzzer in $FUZZERS ; do
  cat >$OUT/$fuzzer.options << EOF
[libfuzzer]
detect_leaks = 0
EOF
done

echo -e "max_len = 250\n" >> $OUT/fuzz-cmd-tag-create.options

# Generate existing file for temp git repository
echo "TEMP1TEMP1TEMP1TEMP1" > $OUT/TEMP_1
echo "TEMP2TEMP2TEMP2TEMP2" > $OUT/TEMP_2
