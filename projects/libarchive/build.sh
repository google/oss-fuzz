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

# For fuzz-introspector. This is to exclude all libxml2 code from the
# fuzz-introspector reports.
export FUZZ_INTROSPECTOR_CONFIG=$SRC/fuzz_introspector_exclusion.config
cat > $FUZZ_INTROSPECTOR_CONFIG <<EOF
FILES_TO_AVOID
libxml2
EOF

DEPS=/deps

cd $SRC/libarchive

mkdir build2
cd build2
cmake -DDONT_FAIL_ON_CRC_ERROR=ON -DENABLE_WERROR=OFF ../
make -j$(nproc)

FUZZ_DIR=$SRC/libarchive/contrib/oss-fuzz
TEST_DIR=$SRC/libarchive/libarchive/test

# Common link flags
LINK_FLAGS="./libarchive/libarchive.a -Wl,-Bstatic -llzo2 -Wl,-Bdynamic -lcrypto -lacl -llzma -llz4 -lbz2 -lz ${DEPS}/libxml2.a"

# Build all fuzzers
FUZZERS=(
    "libarchive_fuzzer"
    "libarchive_tar_fuzzer"
    "libarchive_zip_fuzzer"
    "libarchive_7zip_fuzzer"
    "libarchive_rar_fuzzer"
    "libarchive_rar5_fuzzer"
    "libarchive_xar_fuzzer"
    "libarchive_cab_fuzzer"
    "libarchive_lha_fuzzer"
    "libarchive_iso9660_fuzzer"
    "libarchive_cpio_fuzzer"
    "libarchive_warc_fuzzer"
    "libarchive_mtree_fuzzer"
    "libarchive_ar_fuzzer"
    "libarchive_filter_fuzzer"
    "libarchive_entry_fuzzer"
    "libarchive_write_fuzzer"
    "libarchive_linkify_fuzzer"
    "libarchive_match_fuzzer"
    "libarchive_encryption_fuzzer"
    "libarchive_read_disk_fuzzer"
    "libarchive_write_disk_fuzzer"
    "libarchive_seek_fuzzer"
    "libarchive_string_fuzzer"
    "libarchive_roundtrip_fuzzer"
)

for fuzzer in "${FUZZERS[@]}"; do
    if [ -f "$FUZZ_DIR/${fuzzer}.cc" ]; then
        echo "Building $fuzzer..."
        $CXX $CXXFLAGS -I../libarchive \
            "$FUZZ_DIR/${fuzzer}.cc" -o "$OUT/$fuzzer" \
            $LIB_FUZZING_ENGINE $LINK_FLAGS
    fi
done

# Copy dictionaries and options
cp "$FUZZ_DIR"/*.dict "$OUT/" 2>/dev/null || true
cp "$FUZZ_DIR"/*.options "$OUT/" 2>/dev/null || true

# Build seed corpora
echo "Building seed corpora..."

# Main fuzzer corpus (existing)
cp "$FUZZ_DIR/corpus.zip" "$OUT/libarchive_fuzzer_seed_corpus.zip"

# Function to create corpus from test files
create_corpus() {
    local name=$1
    local pattern=$2
    local dir="/tmp/${name}_corpus"

    mkdir -p "$dir"
    for f in $TEST_DIR/$pattern; do
        if [ -f "$f" ]; then
            base=$(basename "$f" .uu)
            uudecode -o "$dir/$base" "$f" 2>/dev/null || true
        fi
    done

    if [ "$(ls -A $dir 2>/dev/null)" ]; then
        zip -j "$OUT/${name}_seed_corpus.zip" "$dir"/* 2>/dev/null || true
        echo "Created corpus for $name with $(ls $dir | wc -l) files"
    fi
    rm -rf "$dir"
}

# Create format-specific corpora
create_corpus "libarchive_tar_fuzzer" "test_compat_*tar*.uu"
create_corpus "libarchive_zip_fuzzer" "test_*zip*.uu"
create_corpus "libarchive_7zip_fuzzer" "test_read_format_7zip*.uu"
create_corpus "libarchive_rar_fuzzer" "test_read_format_rar_*.uu"
create_corpus "libarchive_rar5_fuzzer" "test_read_format_rar5*.uu"
create_corpus "libarchive_xar_fuzzer" "test_read_format_xar*.uu"
create_corpus "libarchive_cab_fuzzer" "test_read_format_cab*.uu"
create_corpus "libarchive_lha_fuzzer" "test_read_format_lha*.uu"
create_corpus "libarchive_iso9660_fuzzer" "test_read_format_iso*.uu"
create_corpus "libarchive_cpio_fuzzer" "test_compat_cpio*.uu"
create_corpus "libarchive_warc_fuzzer" "test_read_format_warc*.uu"
create_corpus "libarchive_mtree_fuzzer" "test_read_format_mtree*.uu"
create_corpus "libarchive_ar_fuzzer" "test_read_format_ar*.uu"

# Filter corpus - use compressed test files
mkdir -p /tmp/filter_corpus
for f in $TEST_DIR/*.gz.uu $TEST_DIR/*.bz2.uu $TEST_DIR/*.xz.uu $TEST_DIR/*.lz4.uu $TEST_DIR/*.zst.uu $TEST_DIR/*.Z.uu; do
    if [ -f "$f" ]; then
        base=$(basename "$f" .uu)
        uudecode -o "/tmp/filter_corpus/$base" "$f" 2>/dev/null || true
    fi
done
if [ "$(ls -A /tmp/filter_corpus 2>/dev/null)" ]; then
    zip -j "$OUT/libarchive_filter_fuzzer_seed_corpus.zip" /tmp/filter_corpus/* 2>/dev/null || true
fi
rm -rf /tmp/filter_corpus

# Encryption corpus - encrypted archives
mkdir -p /tmp/encryption_corpus
for f in $TEST_DIR/*encrypt*.uu $TEST_DIR/*password*.uu; do
    if [ -f "$f" ]; then
        base=$(basename "$f" .uu)
        uudecode -o "/tmp/encryption_corpus/$base" "$f" 2>/dev/null || true
    fi
done
if [ "$(ls -A /tmp/encryption_corpus 2>/dev/null)" ]; then
    zip -j "$OUT/libarchive_encryption_fuzzer_seed_corpus.zip" /tmp/encryption_corpus/* 2>/dev/null || true
fi
rm -rf /tmp/encryption_corpus

# add the uuencoded test files to main corpus
cd $SRC
mkdir -p ./uudecoded
find $SRC/libarchive/ -type f -name "test_extract.*.uu" -print0 | xargs -0 -I % cp -f % ./uudecoded/ 2>/dev/null || true
cd ./uudecoded
find ./ -name "*.uu" -exec uudecode {} \; 2>/dev/null || true
cd ../
rm -f ./uudecoded/*.uu 2>/dev/null || true
zip -jr $OUT/libarchive_fuzzer_seed_corpus.zip ./uudecoded/* 2>/dev/null || true

# add weird archives from corkami
git clone --depth=1 https://github.com/corkami/pocs
find ./pocs/ -type f -print0 | xargs -0 -I % zip -jr $OUT/libarchive_fuzzer_seed_corpus.zip % 2>/dev/null || true

echo "Build complete! Built ${#FUZZERS[@]} fuzzers."
