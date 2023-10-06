#!/bin/bash -eu
# Copyright 2023 Google LLC
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
pushd $SRC/open5gs

CFLAGS="$CFLAGS -Wno-compound-token-split-by-macro -Wno-format"
CXXFLAGS="$CFLAGS"
LDFLAGS="$CFLAGS"

sed -i "s|link_args: lib_fuzzing_engine|link_args: [lib_fuzzing_engine, '-ltalloc', '-Wl,-rpath,\$ORIGIN/lib']|" tests/fuzzing/meson.build

meson setup builddir --default-library=static -Dfuzzing=true -Dlib_fuzzing_engine="$LIB_FUZZING_ENGINE"
ninja -C builddir -k 0 || true

cp builddir/tests/fuzzing/gtp_message_fuzz $OUT/gtp_message_fuzz
cp builddir/tests/fuzzing/nas_message_fuzz $OUT/nas_message_fuzz

mkdir $OUT/lib/
cp /lib/x86_64-linux-gnu/libtalloc.so* $OUT/lib/

cp tests/fuzzing/gtp_message_fuzz_seed_corpus.zip $OUT/gtp_message_fuzz_seed_corpus.zip
cp tests/fuzzing/nas_message_fuzz_seed_corpus.zip $OUT/nas_message_fuzz_seed_corpus.zip

popd
