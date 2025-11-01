#!/bin/bash -eu
# Copyright 2025 Google LLC
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

MESON_SANITIZER_ARG=

if [ "$SANITIZER" = "address" ] || [ "$SANITIZER" = "undefined" ]; then
    MESON_SANITIZER_ARG="-Db_sanitize=$SANITIZER"
fi

meson setup "$WORK" --wipe --buildtype=debug -Db_lundef=false -Dtls_check=false -Dsysprof=disabled -Dfuzzing=enabled -Dprefer_static=true -Ddefault_library=static -Dintrospection=disabled -Ddocs=disabled -Dtests=false $MESON_SANITIZER_ARG
meson compile -C "$WORK"

find "$WORK/fuzzing" -perm /a+x -type f -exec cp {} "$OUT" \;
find "$SRC/libsoup/fuzzing" -name '*.dict' -exec cp {} "$OUT" \;
