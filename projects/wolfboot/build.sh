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

# Build strategy: drive wolfBoot's own upstream build system. The
# config/examples/library.config recipe produces libwolfboot.a via
# TARGET=library (ARCH=sim, host build, includes wolfCrypt). Module-level
# parsers we want to fuzz are switched in through the upstream Makefile's
# documented knobs (ELF=1, GZIP=1, DELTA_UPDATES=1); the two modules that
# aren't gated by a top-level switch (src/gpt.c, src/fdt.c) are compiled
# via the same Makefile's pattern rules so they pick up exactly the same
# CFLAGS as the rest of the library.
#
# Our fuzzing CFLAGS (sanitizers, libFuzzer instrumentation, ...) reach
# wolfBoot's build through the upstream CFLAGS_EXTRA hook.

WB=$SRC/wolfBoot
FUZZ=$SRC/ada-fuzzers/projects/wolfboot/fuzzer

cd "$WB"
cp config/examples/library.config .config

# Pass-through of OSS-Fuzz CFLAGS. -Wno-error=undefined-internal silences
# a -Werror diagnostic the library config trips when NO_LOADER strips out
# functions that have a static forward-declaration left behind in
# libwolfboot.c; PRINTF_ENABLED keeps the gzip/delta debug stubs linkable.
EXTRA="$CFLAGS -DPRINTF_ENABLED -Wno-error=undefined-internal -Wno-error"

# Build the upstream library plus the two parsers that aren't pulled in
# automatically by TARGET=library. Both invocations use the same
# CFLAGS_EXTRA so every object in the resulting archive agrees on layout
# and instrumentation.
make -j"$(nproc)" libwolfboot.a \
    CC="$CC" \
    ELF=1 GZIP=1 DELTA_UPDATES=1 \
    CFLAGS_EXTRA="$EXTRA"

make -j"$(nproc)" src/gpt.o src/fdt.o \
    CC="$CC" \
    CFLAGS_EXTRA="$EXTRA -DWOLFBOOT_FDT"

# Fold the two extra parser objects into libwolfboot.a so the harness
# link line stays uniform.
ar rcs libwolfboot.a src/gpt.o src/fdt.o

# Harness compile/link. Each harness builds against the parser interface
# from include/, with the per-module configuration define applied so
# header guards line up with how the corresponding parser was compiled.
INCS="-I$WB/include -I$WB/tools/unit-tests"
build_harness() {
    local name="$1" defs="$2"
    $CC $CFLAGS $defs -DPRINTF_ENABLED -DARCH_FLASH_OFFSET=0 $INCS \
        -c $FUZZ/${name}.c -o $WORK/${name}.o
    $CXX $CXXFLAGS \
        $WORK/${name}.o $WB/libwolfboot.a \
        $LIB_FUZZING_ENGINE \
        -o $OUT/${name}
}

build_harness fuzz_elf   "-DWOLFBOOT_ELF"
build_harness fuzz_gpt   ""
build_harness fuzz_gzip  "-DWOLFBOOT_GZIP"
build_harness fuzz_delta "-DDELTA_UPDATES -DDELTA_BLOCK_SIZE=512"

# ---- Seed corpora ----------------------------------------------------------
mkdir -p $WORK/seeds_elf
[ -f /bin/ls ] && head -c 4096 /bin/ls > $WORK/seeds_elf/ls_head
printf '\x7fELF\x02\x01\x01\x00' > $WORK/seeds_elf/elf_magic
(cd $WORK/seeds_elf && zip -qr $OUT/fuzz_elf_seed_corpus.zip .)

mkdir -p $WORK/seeds_gpt
python3 -c "import sys; sys.stdout.buffer.write(b'\x00' + b'\x00'*510 + b'\x55\xaa')" \
    > $WORK/seeds_gpt/mbr_proto
python3 -c "import sys; sys.stdout.buffer.write(b'\x01' + b'EFI PART' + b'\x00'*504)" \
    > $WORK/seeds_gpt/efi_part
(cd $WORK/seeds_gpt && zip -qr $OUT/fuzz_gpt_seed_corpus.zip .)

mkdir -p $WORK/seeds_gzip
python3 -c "import gzip,sys; sys.stdout.buffer.write(gzip.compress(b''))" \
    > $WORK/seeds_gzip/empty.gz
python3 -c "import gzip,sys; sys.stdout.buffer.write(gzip.compress(b'wolfBoot fuzz seed'))" \
    > $WORK/seeds_gzip/short.gz
(cd $WORK/seeds_gzip && zip -qr $OUT/fuzz_gzip_seed_corpus.zip .)

mkdir -p $WORK/seeds_delta
python3 -c "import sys; sys.stdout.buffer.write(b'\x00'*4096 + b'\x7f\x00\x00\x00\x00\x00\x00')" \
    > $WORK/seeds_delta/empty_patch
(cd $WORK/seeds_delta && zip -qr $OUT/fuzz_delta_seed_corpus.zip .)

# ---- Dictionaries ----------------------------------------------------------
cat > $OUT/fuzz_elf.dict <<'EOF'
"\x7fELF"
"\x01"
"\x02"
"\x02\x00"
"\x03\x00"
"\x04\x00"
EOF

cat > $OUT/fuzz_gpt.dict <<'EOF'
"EFI PART"
"\x55\xaa"
"\xee"
EOF

cat > $OUT/fuzz_gzip.dict <<'EOF'
"\x1f\x8b\x08\x00"
"\x1f\x8b\x08\x08"
EOF

cat > $OUT/fuzz_delta.dict <<'EOF'
"\x7f"
EOF
