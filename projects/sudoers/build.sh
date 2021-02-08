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

# Debugging
env

# Some of the sanitizer flags cause issues with configure tests.
# Pull them out of CFLAGS and pass them to configure instead.
if [ $SANITIZER == "coverage" ]; then
    CFLAGS="`echo \"$CFLAGS\" | sed \"s/ $COVERAGE_FLAGS//\"`"
    sanitizer_opts="$COVERAGE_FLAGS"
else
    CFLAGS="`echo \"$CFLAGS\" | sed \"s/ $SANITIZER_FLAGS//\"`"
    sanitizer_opts="$SANITIZER_FLAGS"
fi
# This is already added by --enable-fuzzer
CFLAGS="`echo \"$CFLAGS\" | sed \"s/ -fsanitize=fuzzer-no-link//\"`"

# Build sudo with static libs and enable fuzzing targets.
# All fuzz targets are integrated into the build process.
./configure --disable-shared --disable-shared-libutil --enable-static-sudoers \
    --enable-sanitizer="$sanitizer_opts" --enable-fuzzer \
    --enable-fuzzer-engine="$LIB_FUZZING_ENGINE" --enable-fuzzer-linker="$CXX" \
    --disable-leaks --enable-warnings --enable-werror
make -j$(nproc)

# I/O log fuzzers
cd lib/iolog

# Fuzz legacy I/O log info parser
make fuzz_iolog_legacy && cp fuzz_iolog_legacy $OUT
rm -rf $WORK/corpus
mkdir $WORK/corpus
for f in `find regress/corpus/log_legacy -type f`; do
    cp $f $WORK/corpus/`sha1sum $f | cut -d' ' -f1`
done
zip -j $OUT/fuzz_iolog_legacy_seed_corpus.zip $WORK/corpus/*

# Fuzz I/O log JSON parser
make fuzz_iolog_json && cp fuzz_iolog_json $OUT
rm -rf $WORK/corpus
mkdir $WORK/corpus
for f in `find regress/iolog_json -name '*.in'` `find regress/corpus/log_json -type f`; do
    cp $f $WORK/corpus/`sha1sum $f | cut -d' ' -f1`
done
zip -j $OUT/fuzz_iolog_json_seed_corpus.zip $WORK/corpus/*

# Fuzz I/O log timing file parser
make fuzz_iolog_timing && cp fuzz_iolog_timing $OUT
rm -rf $WORK/corpus
mkdir $WORK/corpus
for f in `find regress/corpus/timing -type f`; do
    cp $f $WORK/corpus/`sha1sum $f | cut -d' ' -f1`
done
zip -j $OUT/fuzz_iolog_timing_seed_corpus.zip $WORK/corpus/*

# Sudoers module fuzzers
cd ../../plugins/sudoers

# Fuzz sudoers parser
make fuzz_sudoers && cp fuzz_sudoers $OUT
rm -rf $WORK/corpus
mkdir $WORK/corpus
for f in ../../examples/sudoers `find regress/sudoers -name '*.in'`; do
    cp $f $WORK/corpus/`sha1sum $f | cut -d' ' -f1`
done
zip -j $OUT/fuzz_sudoers_seed_corpus.zip $WORK/corpus/*

# Fuzz sudoers LDIF parser (used by cvtsudoers)
make fuzz_sudoers_ldif && cp fuzz_sudoers_ldif $OUT
rm -rf $WORK/corpus
mkdir $WORK/corpus
for f in `find regress/sudoers -name '*.ldif.ok' \! -size 0`; do
    cp $f $WORK/corpus/`sha1sum $f | cut -d' ' -f1`
done
zip -j $OUT/fuzz_sudoers_ldif_seed_corpus.zip $WORK/corpus/*

# Fuzz sudoers policy module
make fuzz_policy && cp fuzz_policy $OUT
rm -rf $WORK/corpus
mkdir $WORK/corpus
for f in `find regress/corpus/policy -type f`; do
    cp $f $WORK/corpus/`sha1sum $f | cut -d' ' -f1`
done
zip -j $OUT/fuzz_policy_seed_corpus.zip $WORK/corpus/*

# Cleanup
rm -rf $WORK/corpus
