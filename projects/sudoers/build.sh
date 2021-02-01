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
./configure --enable-static-sudoers --enable-static --disable-shared-libutil
make

# Fuzz json parser
cd lib/iolog/
$CC $CFLAGS $ASAN_CFLAGS -c -I../../include -I../.. -I. $SRC/fuzz_iolog_json_parse.c  -fPIC -DPIC -o .libs/tmp_fuzz
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE .libs/tmp_fuzz -o $OUT/fuzz_iolog_json_parse \
    .libs/libsudo_iolog.a ../eventlog/.libs/libsudo_eventlog.a ../util/.libs/libsudo_util.a

# Fuzz libsudoers parsing
cd ../../plugins/sudoers
$CC $CFLAGS $ASAN_CFLAGS -c -I../../include -I../.. -I.  $SRC/fuzz_sudoers_parse.c  -fPIC -DPIC -o fuzz_sudoers_parse.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_sudoers_parse.o -o $OUT/fuzz_sudoers_parse \
    ./.libs/libparsesudoers.a ./.libs/sudoers.a  net_ifs.o parse_ldif.o ldap_util.o -lcrypt
