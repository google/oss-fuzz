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

MESON_FUZZING_ARG="-Dfuzzing=enabled"
if [ "$FUZZING_ENGINE" != "libfuzzer" ]; then
    MESON_FUZZING_ARG="-Dfuzzing=disabled"
fi

meson setup "$WORK" --wipe --buildtype=debug -Db_lundef=false -Dtls_check=false -Dsysprof=disabled $MESON_FUZZING_ARG -Dprefer_static=true -Ddefault_library=static -Dintrospection=disabled -Ddocs=disabled -Dtests=false $MESON_SANITIZER_ARG
meson compile -C "$WORK"

if [ "$FUZZING_ENGINE" = "libfuzzer" ]; then
    find "$WORK/fuzzing" -perm /a+x -type f -exec cp {} "$OUT" \;
else
    # For non-libfuzzer engines (e.g. AFL), manually compile fuzz targets
    # using $LIB_FUZZING_ENGINE since meson's fuzzing support requires libfuzzer.
    export PKG_CONFIG_PATH="$WORK/meson-uninstalled:${PKG_CONFIG_PATH:-}"
    LIBSOUP_CFLAGS=$(pkg-config --cflags libsoup-3.0)
    LIBSOUP_LIBS=$(pkg-config --static --libs libsoup-3.0)

    for target in fuzz_decode_data_uri fuzz_cookie_parse fuzz_content_sniffer fuzz_date_time fuzz_header_parsing fuzz_headers_parse_request fuzz_headers_parse_response; do
        $CC $CFLAGS -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION \
            $LIBSOUP_CFLAGS \
            -c "$SRC/libsoup/fuzzing/${target}.c" -o "$WORK/${target}.o"
        $CXX $CXXFLAGS \
            "$WORK/${target}.o" -o "$OUT/${target}" \
            $LIB_FUZZING_ENGINE \
            -Wl,--start-group $LIBSOUP_LIBS -Wl,--end-group
    done
fi

find "$SRC/libsoup/fuzzing" -name '*.dict' -exec cp {} "$OUT" \;
