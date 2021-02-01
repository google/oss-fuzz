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

# Move ASAN-specific flags into ASAN_CFLAGS and ASAN_LDFLAGS
# That way they don't affect configure but will get used when building.
if [ $SANITIZER == "coverage" ]; then
    export ASAN_CFLAGS="$COVERAGE_FLAGS"
    export ASAN_LDFLAGS="$COVERAGE_FLAGS"
    CFLAGS="`echo \"$CFLAGS\" | sed \"s/ $COVERAGE_FLAGS//\"`"
else
    export ASAN_CFLAGS="$SANITIZER_FLAGS"
    export ASAN_LDFLAGS="$SANITIZER_FLAGS"
    CFLAGS="`echo \"$CFLAGS\" | sed \"s/ $SANITIZER_FLAGS//\"`"
fi

# Build sudo with static libs for simpler fuzzing
./configure --enable-static-sudoers --enable-static --disable-shared-libutil \
    --disable-leaks --enable-warnings --enable-werror
make -j$(nproc)

# Fuzz I/O log JSON parser
cd lib/iolog
$CC $CFLAGS $ASAN_CFLAGS -c -I../../include -I../.. -I. \
    regress/fuzz/fuzz_iolog_json.c
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE -o $OUT/fuzz_iolog_json \
    fuzz_iolog_json.o .libs/libsudo_iolog.a \
    ../eventlog/.libs/libsudo_eventlog.a ../util/.libs/libsudo_util.a

# Corpus for fuzzing I/O log JSON parser
mkdir $WORK/corpus
for f in `find regress/iolog_json -name '*.in'`; do
    cp $f $WORK/corpus/`sha1sum $f | cut -d' ' -f1`
done
zip -j $OUT/fuzz_iolog_json_seed_corpus.zip $WORK/corpus/*
rm -rf $WORK/corpus

# Fuzz sudoers parser
cd ../../plugins/sudoers
$CC $CFLAGS $ASAN_CFLAGS -c -I../../include -I../.. -I. \
    regress/fuzz/fuzz_sudoers.c
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE -o $OUT/fuzz_sudoers \
    fuzz_sudoers.o locale.o stubs.o sudo_printf.o \
    .libs/libparsesudoers.a ../../lib/util/.libs/libsudo_util.a

# Corpus for fuzzing sudoers parser
mkdir $WORK/corpus
for f in sudoers `find regress/sudoers -name '*.in'`; do
    cp $f $WORK/corpus/`sha1sum $f | cut -d' ' -f1`
done
zip -j $OUT/fuzz_sudoers_seed_corpus.zip $WORK/corpus/*
rm -rf $WORK/corpus

# Fuzz sudoers LDIF parser (used by cvtsudoers)
cd ../../plugins/sudoers
$CC $CFLAGS $ASAN_CFLAGS -c -I../../include -I../.. -I. \
    regress/fuzz/fuzz_sudoers_ldif.c
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE -o $OUT/fuzz_sudoers_ldif \
    fuzz_sudoers_ldif.o parse_ldif.o ldap_util.o fmtsudoers.o locale.o stubs.o \
    sudo_printf.o .libs/libparsesudoers.a ../../lib/util/.libs/libsudo_util.a

# Corpus for fuzzing sudoers LDIF parser
mkdir $WORK/corpus
for f in `find regress/sudoers -name '*.ldif.ok' \! -size 0`; do
    cp $f $WORK/corpus/`sha1sum $f | cut -d' ' -f1`
done
zip -j $OUT/fuzz_sudoers_ldif_seed_corpus.zip $WORK/corpus/*
rm -rf $WORK/corpus
