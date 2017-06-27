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

# variables
target_dir="$SRC/fuzz-targets"
LDFLAGS=""
LDLIBS="-lwolfssl -lFuzzingEngine"



# build project
./autogen.sh
./configure --enable-static --disable-shared --prefix=/usr CC="clang"
make -j$(nproc) all
make install



# set up fuzz targets
for each in "${target_dir}"/*/target.c; do
    [ -d "${each}" ] && continue
    [ -f "${each}" ] || continue

    path=$(dirname "${each}")
    target=$(basename "${path}")

    # build fuzz target
    $CC $CFLAGS -I./fuzz \
        -c "${path}/target.c" -o "$WORK/${target}.o"

    $CXX $CXXFLAGS \
        "$WORK/${target}.o" -o "$OUT/${target}" \
        $LDFLAGS $LDLIBS

    # copy only one options file, if any
    options=$(find "${path}" -type f -iname '*.options' | head -n 1)
    if [ -f "${options}" ]; then
        cp "${options}" "$OUT/${target}.options"
    fi

    # copy only one corpus directory, if any
    corpus=$(find "${path}" -type d -iname '*corpus' | head -n 1)
    if [ -d "${corpus}" ]; then
        zip -q "$OUT/${target}_seed_corpus.zip" -r "${corpus}"
    fi
done

# copy dictionaries, if any
for each in "$target_dir"/*.dict; do
    [ -d "${each}" ] && continue
    [ -f "${each}" ] || continue

    cp "${each}" "$OUT/"
done
