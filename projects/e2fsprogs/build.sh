#!/bin/bash -eu
# Copyright 2020 Google Inc.
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

# build project
export LDFLAGS="$CXXFLAGS"
$SRC/e2fsprogs/configure
make -j$(nproc) all

# build fuzzers
for fuzzer in $(find $SRC/fuzz -name '*_fuzzer.cc'); do
  fuzzer_basename=$(basename -s .cc $fuzzer)
  $CXX $CXXFLAGS \
      $LIB_FUZZING_ENGINE \
      -I $SRC/e2fsprogs/lib \
      $fuzzer \
      -L'./lib/ext2fs' -lext2fs \
      -L'./lib/et' -lcom_err \
      -o $OUT/$fuzzer_basename
done

# Build a seed corpus from upstream test images. The e2fsprogs tree carries
# compressed ext2/3/4 filesystem images under tests/ — these are the
# regression inputs for e2fsck/debugfs/etc. Reusing them lets the fuzzers
# start past ext2fs_open's superblock magic check on iteration 1.
seed_stage=$(mktemp -d)
# Cap at compressed size 20K (decompressed ~100KB–1MB) to keep each seed
# under the 1 MiB max_len set below. Bigger ones (e.g. f_large_dir) blow
# past max_len and would be discarded anyway.
for img in $(find $SRC/e2fsprogs/tests -name 'image.gz' -size -20k); do
  tag=$(basename "$(dirname "$img")")
  gunzip -c "$img" > "$seed_stage/$tag.img"
  # Trim oversized seeds — libFuzzer would skip files past max_len.
  if [ $(stat -c%s "$seed_stage/$tag.img") -gt 1048576 ]; then
    rm "$seed_stage/$tag.img"
  fi
done
for img in $(find $SRC/e2fsprogs/tests -name 'image.bz2' -size -20k); do
  tag=$(basename "$(dirname "$img")")
  bunzip2 -c "$img" > "$seed_stage/$tag.img"
  if [ $(stat -c%s "$seed_stage/$tag.img") -gt 1048576 ]; then
    rm "$seed_stage/$tag.img"
  fi
done
# Also generate fresh mke2fs images covering feature combinations the upstream
# test corpus underrepresents (MMP, casefold, encrypt, bigalloc, 64bit) — each
# unlocks chunks of mmp.c / nls_utf8.c / bitmap64 / etc. that the test images
# never reach.
gen_image() {
  local out="$1"; shift
  local size_kb="${1:-128}"; shift || true
  local img="$seed_stage/$out"
  truncate -s "${size_kb}K" "$img"
  ./misc/mke2fs -F -q "$@" "$img" 2>/dev/null || rm -f "$img"
}
gen_image fresh_ext2.img         512 -t ext2
gen_image fresh_ext4.img         256 -t ext4
gen_image fresh_64bit.img        256 -t ext4 -O 64bit,extents,has_journal
gen_image fresh_journal.img      1024 -t ext4 -O has_journal,extents,64bit -J size=1
gen_image fresh_mmp.img          512 -t ext4 -O mmp
gen_image fresh_casefold.img     256 -t ext4 -O casefold,extents
gen_image fresh_bigalloc.img     1024 -t ext4 -O bigalloc,extents,64bit -C 4096
gen_image fresh_meta_bg.img      512 -t ext4 -O meta_bg,64bit
gen_image fresh_inlinedata.img   256 -t ext4 -O inline_data,extents
gen_image fresh_encrypt.img      256 -t ext4 -O encrypt,extents,64bit
gen_image fresh_verity.img       256 -t ext4 -O verity,extents,64bit
gen_image fresh_fastcommit.img   1024 -t ext4 -O fast_commit,extents,has_journal,64bit
gen_image fresh_project.img      256 -t ext4 -O project,quota,extents,64bit
gen_image fresh_ea_inode.img     256 -t ext4 -O ea_inode,extents,64bit
gen_image fresh_extra_isize.img  256 -t ext4 -O extents,64bit -I 256
gen_image fresh_cf_encrypt.img   256 -t ext4 -O casefold,encrypt,extents,64bit
gen_image fresh_orphan_file.img  256 -t ext4 -O orphan_file,extents,has_journal,64bit
gen_image fresh_bs1024.img       512 -t ext4 -O extents,64bit -b 1024
gen_image fresh_bs2048.img       512 -t ext4 -O extents,64bit -b 2048
gen_image fresh_no_extents.img   256 -t ext4 -O ^extents,has_journal,64bit
gen_image fresh_huge_files.img   256 -t ext4 -O huge_file,extents,64bit
gen_image fresh_metadata_csum.img 256 -t ext4 -O metadata_csum,extents,64bit
gen_image fresh_quota.img        256 -t ext4 -O quota,extents,has_journal,64bit

# Per-harness seed corpus: run each seed through the harness once and keep
# only the ones that pass cleanly, so libFuzzer doesn't bail during initial
# corpus load.
for fuzzer in $(find $SRC/fuzz -name '*_fuzzer.cc'); do
  fuzzer_basename=$(basename -s .cc $fuzzer)
  harness_seeds=$(mktemp -d)
  cp -r "$seed_stage"/. "$harness_seeds/"
  for seed in "$harness_seeds"/*; do
    [ -f "$seed" ] || continue
    if ! ASAN_OPTIONS=detect_leaks=0:exitcode=77 \
         timeout 3 "$OUT/$fuzzer_basename" "$seed" >/dev/null 2>&1; then
      rm "$seed"
    fi
  done
  rm -f "$OUT/${fuzzer_basename}_seed_corpus.zip"
  (cd "$harness_seeds" && zip -q -r "$OUT/${fuzzer_basename}_seed_corpus.zip" .)
  rm -rf "$harness_seeds"
  # Raise max_len above the typical 100KB image size — libFuzzer's default
  # 4096-byte cap would otherwise discard every seed.
  cat > "$OUT/${fuzzer_basename}.options" <<EOF
[libfuzzer]
max_len = 1048576
EOF
done

rm -rf "$seed_stage"
