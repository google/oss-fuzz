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

# build fuzzers
make -j$(nproc) CC=$CC CXX=$CXX CFLAGS="$CFLAGS" \
  FUZZ_CXXFLAGS="$CXXFLAGS -Wl,--allow-multiple-definition" \
  LIB_FUZZING_ENGINE="common-main.o $LIB_FUZZING_ENGINE" fuzz-all

FUZZERS="fuzz-pack-headers fuzz-pack-idx fuzz-commit-graph"
#FUZZERS="$FUZZERS fuzz-commit-graph-get-filename fuzz-commit-graph-lookup"
#FUZZERS="$FUZZERS fuzz-commit-graph-parse-commit fuzz-commit-graph-verify"
#FUZZERS="$FUZZERS fuzz-commit-graph-get-graph fuzz-commit-graph-open"
#FUZZERS="$FUZZERS fuzz-commit-graph-handle fuzz-commit-graph-write"
FUZZERS="$FUZZERS fuzz-cmd-status fuzz-cmd-version"
#FUZZERS="$FUZZERS fuzz-cmd-add-commit fuzz-cmd-diff fuzz-cmd-branch"
#FUZZERS="$FUZZERS fuzz-cmd-grep fuzz-cmd-ls fuzz-cmd-mv fuzz-cmd-cherry"

# copy fuzzers
for fuzzer in $FUZZERS ; do
  cp oss-fuzz/$fuzzer $OUT
done

# build corpora from Git's own packfiles
zip -j $OUT/fuzz-pack-idx_seed_corpus.zip .git/objects/pack/*.idx
for packfile in .git/objects/pack/*.pack ; do
  dd ibs=1 skip=12 if=$packfile of=$packfile.trimmed
done
zip -j $OUT/fuzz-pack-headers_seed_corpus.zip .git/objects/pack/*.pack.trimmed

# build commit-graph corpus
ASAN_OPTIONS=detect_leaks=0 ./git commit-graph write
zip -j $OUT/fuzz-commit-graph_seed_corpus .git/objects/info/commit-graph

# build seed corpus for all cmd fuzz
for fuzzname in $FUZZERS; do
  if [[ $fuzzname == fuzz-cmd-* ]]; then
    dd if=/dev/random of=$SRC/$fuzzname.seed bs=1 count=1024
    zip -j $OUT/${fuzzname}_seed_corpus.zip $SRC/$fuzzname.seed
    rm $SRC/$fuzzname.seed
  fi
done

# Mute stderr
for fuzzer in $FUZZERS ; do
  cat >$OUT/$fuzzer.options << EOF
[libfuzzer]
close_fd_mask = 2
EOF
done

# Generate existing file for temp git repository
dd if=/dev/random of=$OUT/TEMP_1 bs=1 count=20
dd if=/dev/random of=$OUT/TEMP_2 bs=1 count=20

# Prepare initial git repository
mkdir -p /tmp/oss-test.git
rm -rf /tmp/oss-test.git/*
rm -rf /tmp/backup.git
cd /tmp/oss-test.git
git init --bare
cd $OUT
rm -rf $OUT/.git
git init
git config --global user.name "FUZZ"
git config --global user.email "FUZZ@LOCALHOST"
git config --global --add safe.directory '*'
git remote add origin /tmp/oss-test.git
git add ./TEMP_1 ./TEMP_2
git commit -m"First Commit"
git push origin master

# Create backup for reset
cp -r /tmp/oss-test.git /tmp/backup.git
