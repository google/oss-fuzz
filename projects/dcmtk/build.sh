#!/bin/bash -eu

FUZZERS=(
  dcmtk_dicom_fuzzer
  dcmtk_meta_fuzzer
)

cd "$SRC"
cmake -S dcmtk -B dcmtk-build   -DBUILD_SHARED_LIBS=OFF   -DDCMTK_WITH_OPENSSL=OFF   -DDCMTK_WITH_PNG=OFF   -DDCMTK_WITH_TIFF=OFF   -DDCMTK_WITH_XML=OFF   -DDCMTK_WITH_ICONV=ON   -DDCMTK_WITH_ZLIB=ON   -DCMAKE_BUILD_TYPE=Release   -DCMAKE_INSTALL_PREFIX="$WORK/dcmtk-install"
cmake --build dcmtk-build -j"$(nproc)"
cmake --install dcmtk-build

DICT_SRC=$(ls "$WORK"/dcmtk-install/share/dcmtk-*/dicom.dic 2>/dev/null || true)
if [ -n "$DICT_SRC" ]; then
  cp "$DICT_SRC" "$OUT/dicom.dic" || true
fi

cd "$SRC/dcmtk-fuzzers"
DCMTK_INC="$WORK/dcmtk-install/include"
DCMTK_LIBDIR="$WORK/dcmtk-install/lib"

export PKG_CONFIG_PATH="$DCMTK_LIBDIR/pkgconfig:${PKG_CONFIG_PATH:-}"
RAW_LIBS="$(pkg-config --static --libs dcmtk 2>/dev/null || true)"
FILTERED_LIBS=""
for tok in $RAW_LIBS; do
  if [[ "$tok" == -l* ]]; then
    lib="${tok#-l}"
    if [ -f "$DCMTK_LIBDIR/lib${lib}.a" ] || [ -f "$DCMTK_LIBDIR/lib${lib}.so" ]; then
      FILTERED_LIBS+=" $tok"
    fi
  else
    FILTERED_LIBS+=" $tok"
  fi
done
[ -z "$FILTERED_LIBS" ] && FILTERED_LIBS="-ldcmdata -loflog -lofstd -loficonv -lz"
DCMTK_LIBS="-Wl,--start-group ${FILTERED_LIBS} -Wl,--end-group -lpthread -ldl"

build_one() {
  local src="$1"
  local out="$2"
  "$CXX" $CXXFLAGS -std=c++17 -I"$DCMTK_INC"     "$src" -o "$OUT/$out"     $LIB_FUZZING_ENGINE -L"$DCMTK_LIBDIR" ${DCMTK_LIBS}
}

for fz in "${FUZZERS[@]}"; do
  echo "Building $fz..."
  build_one "${fz}.cc" "$fz"
done

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

python3 "$SRC/dcmtk-fuzzers/make_seed_corpus.py"

cp "$SRC/dcmtk-fuzzers/dcmtk_dicom_fuzzer.dict" "$OUT/dcmtk_dicom_fuzzer.dict" || true
cp "$SRC/dcmtk-fuzzers/dcmtk_dicom_fuzzer.dict" "$OUT/dcmtk_meta_fuzzer.dict" || true
