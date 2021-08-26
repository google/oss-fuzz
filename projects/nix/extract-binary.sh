#!/usr/bin/env bash
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

binary=$1
store_libraries="$(ldd $binary | grep -v linux-vdso.so | sed -E 's/.*=> (\/nix\/store.*) .*/\1/')"

mkdir -p "$OUT/lib"

for lib in $store_libraries; do
    echo "copying $lib"
    cp "$lib" "$OUT/lib"

    libMoved="$OUT/lib/$(basename $lib)"
    echo "patching $libMoved"
    chmod +w "$libMoved"
    patchelf \
        --set-rpath '$ORIGIN' \
        "$libMoved"
done

echo "copying $binary"
cp "$binary" "$OUT"

binaryMoved="$OUT/$(basename $binary)"
echo "patching $binaryMoved"
chmod +w "$binaryMoved"
patchelf \
    --set-rpath '$ORIGIN/lib' \
    "$binaryMoved"
