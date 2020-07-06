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

export CXXFLAGS="$CXXFLAGS -DHB_NO_MT -DHAVE_GETPAGESIZE -DHAVE_STDBOOL_H -DHAVE_MMAP -DHAVE_UNISTD_H -DHAVE_SYS_MMAN_H -DHAVE_SYSCONF -DHAVE_ATEXIT"
export CXXFLAGS="$CXXFLAGS src/harfbuzz.cc -Isrc"

# Build the fuzzers.
$CXX $LIB_FUZZING_ENGINE $CXXFLAGS test/fuzzing/hb-shape-fuzzer.cc -o $OUT/hb-shape-fuzzer
$CXX $LIB_FUZZING_ENGINE $CXXFLAGS test/fuzzing/hb-draw-fuzzer.cc -o $OUT/hb-draw-fuzzer
$CXX $LIB_FUZZING_ENGINE $CXXFLAGS src/hb-subset*.cc test/fuzzing/hb-subset-fuzzer.cc -o $OUT/hb-subset-fuzzer
$CXX $LIB_FUZZING_ENGINE $CXXFLAGS test/fuzzing/hb-set-fuzzer.cc -o $OUT/hb-set-fuzzer

# Archive and copy to $OUT seed corpus if the build succeeded.
mkdir all-fonts
for d in \
	test/shaping/data/in-house/fonts \
	test/shaping/data/aots/fonts \
	test/shaping/data/text-rendering-tests/fonts \
	test/api/fonts \
	test/fuzzing/fonts \
	perf/fonts \
	; do
	cp $d/* all-fonts/
done
zip $OUT/hb-shape-fuzzer_seed_corpus.zip all-fonts/*
cp $OUT/hb-shape-fuzzer_seed_corpus.zip $OUT/hb-draw-fuzzer_seed_corpus.zip
cp $OUT/hb-shape-fuzzer_seed_corpus.zip $OUT/hb-subset-fuzzer_seed_corpus.zip
zip $OUT/hb-set-fuzzer_seed_corpus.zip ./test/fuzzing/sets/*
