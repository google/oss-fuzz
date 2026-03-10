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

cd $SRC/u-boot

# 0. Patch u-boot source
git apply $SRC/oss-fuzz.patch

# 1. Configure: sandbox + fuzz + all fuzzer target dependencies
make sandbox_defconfig CC="$CC" HOSTCC="$CC"
./scripts/config --enable CONFIG_FUZZ
./scripts/config --enable CONFIG_DM_FUZZING_ENGINE
./scripts/config --enable CONFIG_FUZZING_ENGINE_SANDBOX
./scripts/config --disable CONFIG_EFI_CAPSULE_AUTHENTICATE
./scripts/config --disable CONFIG_LTO
./scripts/config --disable CONFIG_OF_SEPARATE
./scripts/config --enable CONFIG_OF_EMBED
./scripts/config --set-str CONFIG_DEFAULT_DEVICE_TREE "test"
# Decompressors
./scripts/config --enable CONFIG_GZIP
./scripts/config --enable CONFIG_BZIP2
./scripts/config --enable CONFIG_LZMA
./scripts/config --enable CONFIG_LZO
./scripts/config --enable CONFIG_LZ4
./scripts/config --enable CONFIG_ZSTD
# Filesystems
./scripts/config --enable CONFIG_FS_BTRFS
./scripts/config --enable CONFIG_CMD_BTRFS
make olddefconfig CC="$CC" HOSTCC="$CC"

# 2. Build u-boot sandbox
#    NO_PYTHON=1 skips pylibfdt (_libfdt.so) resulting in  no shared libraries.
#    CONFIG_BINMAN= overrides the Makefile variable so binman (which
#    needs pylibfdt) never runs.  Sandbox doesn't need binman.
make -j$(nproc) CROSS_COMPILE="" CC="$CC" HOSTCC="$CC" NO_PYTHON=1 \
    CONFIG_BINMAN= KCFLAGS="$CFLAGS"

# 3. Install all fuzzers (same binary, different names)
FUZZERS="
    fuzz_efi_load_image
    fuzz_fit_image_load
    fuzz_image_decomp
    fuzz_btrfs
"

for fuzzer in $FUZZERS; do
    cp u-boot $OUT/$fuzzer

    cat > $OUT/$fuzzer.options <<EOF
[libfuzzer]
detect_leaks=0
[asan]
detect_leaks=0
EOF
done

