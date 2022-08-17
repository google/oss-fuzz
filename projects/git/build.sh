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

# copy fuzzers
for fuzzer in $FUZZERS ; do
  cp $fuzzer $OUT
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

# Mute stderr
for fuzzer in $FUZZERS ; do
  cat >$OUT/$fuzzer.options << EOF
[libfuzzer]
close_fd_mask = 2
EOF
done
