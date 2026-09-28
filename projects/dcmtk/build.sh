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

FUZZERS=(
  dcmtk_dicom_fuzzer
  dcmtk_meta_fuzzer
  dcmtk_image_fuzzer
)

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

cd "$SRC/dcmtk-fuzzers"
DCMTK_INC="$WORK/dcmtk-install/include"
DCMTK_LIBDIR="$WORK/dcmtk-install/lib"

# Derive robust link set from pkg-config and filter to installed libs.
export PKG_CONFIG_PATH="$DCMTK_LIBDIR/pkgconfig:${PKG_CONFIG_PATH:-}"
RAW_LIBS="$(pkg-config --static --libs dcmtk 2>/dev/null || true)"
FILTERED_LIBS=""
for tok in $RAW_LIBS; do
  # Keep every token: -L paths, -l libs (both DCMTK and system ones like -lz)
  FILTERED_LIBS+=" $tok"
done
[ -z "$FILTERED_LIBS" ] && FILTERED_LIBS="-ldcmdata -loflog -lofstd -loficonv -lz"
DCMTK_LIBS="-Wl,--start-group ${FILTERED_LIBS} -Wl,--end-group -lpthread -ldl"

# The image/codec decode pipeline needs the image, imgle and codec static
# libraries. pkg-config's "dcmtk" set typically only covers the core parsing
# libraries (dcmdata/oflog/ofstd/oficonv), so append the extra ones explicitly,
# ordered with the higher-level image/codec libs before dcmdata. They are all
# wrapped in a single --start-group so circular references resolve.
echo "Installed DCMTK static libs:"
ls "$DCMTK_LIBDIR"/lib*.a 2>/dev/null || true

IMAGE_EXTRA="-ldcmimage -ldcmimgle -ldcmjpeg -ldcmjpls -lijg8 -lijg12 -lijg16 -ldcmtkcharls"
IMAGE_CORE="-ldcmdata -loflog -lofstd -loficonv -lz"
DCMTK_IMAGE_LIBS="-Wl,--start-group ${IMAGE_EXTRA} ${IMAGE_CORE} -Wl,--end-group -lpthread -ldl"

build_one() {
  local src="$1"
  local base_out="$2"
  local libs="$3"
  "$CXX" $CXXFLAGS -std=c++17 -I"$DCMTK_INC" \
    "$src" -o "$OUT/$base_out" \
    $LIB_FUZZING_ENGINE -L"$DCMTK_LIBDIR" ${libs}
}

for fz in "${FUZZERS[@]}"; do
  echo "Building $fz..."
  if [ "$fz" = "dcmtk_image_fuzzer" ]; then
    build_one "${fz}.cc" "$fz" "$DCMTK_IMAGE_LIBS"
  else
    build_one "${fz}.cc" "$fz" "$DCMTK_LIBS"
  fi
done

# .options: use *relative* dictionary path so check_build works after files are copied.
cat > "$OUT/dcmtk_dicom_fuzzer.options" << 'EOF'
[libfuzzer]
max_len = 131072
timeout = 25
rss_limit_mb = 2560
dict = dcmtk_dicom_fuzzer.dict
EOF

cat > "$OUT/dcmtk_meta_fuzzer.options" << 'EOF'
[libfuzzer]
max_len = 65536
timeout = 25
rss_limit_mb = 2560
dict = dcmtk_dicom_fuzzer.dict
EOF

cat > "$OUT/dcmtk_image_fuzzer.options" << 'EOF'
[libfuzzer]
max_len = 262144
timeout = 25
rss_limit_mb = 2560
dict = dcmtk_dicom_fuzzer.dict
EOF

# Seed corpus next to binaries
python3 $SRC/dcmtk-fuzzers/make_seed_corpus.py $OUT/dcmtk_dicom_fuzzer_seed_corpus.zip

# Copy dictionary next to binaries under both names (defensive)
cp "$SRC/dcmtk-fuzzers/dcmtk_dicom_fuzzer.dict" "$OUT/dcmtk_dicom_fuzzer.dict" || true
cp "$SRC/dcmtk-fuzzers/dcmtk_dicom_fuzzer.dict" "$OUT/dcmtk_meta_fuzzer.dict" || true

# Share the DICOM seed corpus with the image fuzzer as a starting point.
cp "$OUT/dcmtk_dicom_fuzzer_seed_corpus.zip" "$OUT/dcmtk_image_fuzzer_seed_corpus.zip" 2>/dev/null || true
