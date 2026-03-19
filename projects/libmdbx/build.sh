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

cd $SRC/libmdbx

export MAKE=$SRC/make-"$MAKE_VERSION"/make

$MAKE clean || true
$MAKE libmdbx.a CC="$CC" CFLAGS="$CFLAGS"

cp ./fuzz/seed/fuzz_raw_db_format_seed_corpus.zip $OUT

$CC $CFLAGS -I./ -I./fuzz \
  ./fuzz/fuzz_raw_db_format.c \
  ./libmdbx.a \
  -o $OUT/fuzz_raw_db_format \
  $LIB_FUZZING_ENGINE
