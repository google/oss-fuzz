#!/bin/bash -eu
# Copyright 2026 Google LLC
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

# Build DCMTK (static) with iconv enabled so liboficonv is present.
cd "$SRC"
cmake -S dcmtk -B dcmtk-build \
  -DBUILD_SHARED_LIBS=OFF \
  -DDCMTK_WITH_OPENSSL=OFF \
  -DDCMTK_WITH_PNG=OFF \
  -DDCMTK_WITH_TIFF=OFF \
  -DDCMTK_WITH_XML=OFF \
  -DDCMTK_WITH_ICONV=ON \
  -DDCMTK_WITH_ZLIB=ON \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$WORK/dcmtk-install"
cmake --build dcmtk-build -j"$(nproc)"
cmake --install dcmtk-build

# Ship the DICOM dictionary (for cleaner logs at runtime).
DICT_SRC=$(ls "$WORK"/dcmtk-install/share/dcmtk-*/dicom.dic 2>/dev/null || true)
if [ -n "$DICT_SRC" ]; then
  cp "$DICT_SRC" "$OUT/dicom.dic" || true
fi

# Build the fuzzers.
"$SRC/dcmtk-fuzzers/build.sh"

# Copy the dictionary and write options for each fuzzer.
for f in "$OUT"/*_fuzzer; do
  name="$(basename "$f")"
  cp "$SRC/dcmtk_fuzzer.dict" "$OUT/$name.dict"
  cat > "$OUT/$name.options" << EOF
[libfuzzer]
max_len = 262144
timeout = 25
rss_limit_mb = 2560
dict = $name.dict
EOF
done
