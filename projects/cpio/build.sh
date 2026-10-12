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
################################################################################

cd $SRC/cpio

# cpio ships no ./configure: generate it and import gnulib/paxutils. The two
# submodules were cloned in the Dockerfile, so bootstrap runs offline (--no-git).
./bootstrap --no-git --gnulib-srcdir=$SRC/cpio/gnulib --skip-po

# Configure with OSS-Fuzz's $CC/$CFLAGS (picked up from the environment).
./configure --disable-dependency-tracking --disable-nls

# Build only what the harness links against; skip doc/ (needs makeinfo), po/, tests/.
make -C gnu -j$(nproc)
make -C lib -j$(nproc)

# cpio_SOURCES (src/Makefile.am). Build the objects without linking the cpio binary.
CPIO_OBJS="copyin.o copyout.o copypass.o defer.o dstring.o global.o fatal.o \
           tar.o util.o filemode.o idcache.o makepath.o userspec.o"
make -C src -j$(nproc) $CPIO_OBJS main.o

# Recompile main.c with its main() renamed so libFuzzer owns the entry point,
# while keeping initialize_buffers()/copyin_buf_size() available for the harness.
(cd src && $CC $CFLAGS -DHAVE_CONFIG_H -I. -I.. -I../gnu -I../lib \
    -Dmain=cpio_cli_main_unused -c main.c -o main.o)

# Compile the fuzz harness as an extra src/ translation unit (same flags as copyin.c).
cp $SRC/fuzz_cpio.c src/
(cd src && $CC $CFLAGS -DHAVE_CONFIG_H -I. -I.. -I../gnu -I../lib \
    -c fuzz_cpio.c -o fuzz_cpio.o)

# Link: harness + all cpio objects (renamed main.o included) + gnulib/paxutils
# archives + fuzzing engine. exit() is wrapped so corrupt-input exit(1) returns
# into the harness instead of killing the fuzzer.
$CXX $CXXFLAGS \
    src/fuzz_cpio.o \
    src/copyin.o src/copyout.o src/copypass.o src/defer.o src/dstring.o \
    src/global.o src/fatal.o src/tar.o src/util.o src/filemode.o \
    src/idcache.o src/makepath.o src/userspec.o src/main.o \
    lib/libpax.a gnu/libgnu.a \
    -Wl,--wrap=exit -Wl,--wrap=error -Wl,--wrap=error_at_line \
    -Wl,--wrap=xmalloc -Wl,--wrap=xrealloc -Wl,--wrap=xcalloc \
    -Wl,--wrap=xreallocarray -Wl,--wrap=x2realloc -Wl,--wrap=x2nrealloc \
    -Wl,--wrap=rpl_free \
    $LIB_FUZZING_ENGINE \
    -o $OUT/fuzz_cpio

# Per-target libFuzzer options. cpio is a short-lived CLI that exit()s on
# malformed input without freeing its buffers (normal for such a program). Driven
# in-process, those abandoned allocations look like leaks to LSAN, so disable leak
# detection for this target; ASan's use-after-free / out-of-bounds / overflow
# detection (the memory-safety bugs that matter) stays fully active.
cat > $OUT/fuzz_cpio.options <<'OPTS'
[libfuzzer]
detect_leaks=0
max_len=65536
OPTS

# Seed corpus: small valid archives in cpio's on-disk formats (new ASCII, old
# ASCII/ODC, CRC, old binary), each with a regular file, a file in a subdir, and
# the TRAILER!!! record, so the fuzzer starts from well-formed headers.
# Best-effort: never fail the build over seed generation.
set +e
mkdir -p seeds
base64 -d > seeds/seed_newc.cpio <<'B64'
MDcwNzAxMDAwMDlGNDcwMDAwODFCNDAwMDAwM0U4MDAwMDAzRTgwMDAwMDAwMTZBQ0QwQ0I1MDAwMDAwMDYwMDAwMDAwMDAwMDAwMDJEMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA2MDAwMDAwMDBhLnR4dABoZWxsbwoAADA3MDcwMTAwMDA5RjQ4MDAwMDgxQjQwMDAwMDNFODAwMDAwM0U4MDAwMDAwMDE2QUNEMENCNTAwMDAwMDA4MDAwMDAwMDAwMDAwMDAyRDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwNjAwMDAwMDAwYi50eHQAd29ybGQhIQowNzA3MDEwMDAwOUY0QTAwMDA4MUI0MDAwMDAzRTgwMDAwMDNFODAwMDAwMDAxNkFDRDBDQjUwMDAwMDAwMTAwMDAwMDAwMDAwMDAwMkQwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMEEwMDAwMDAwMHN1Yi9jLnR4dAB4AAAAMDcwNzAxMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMTAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwQjAwMDAwMDAwVFJBSUxFUiEhIQAAAAAAAAAAAAAAAAAAAAAAAAAA
B64
base64 -d > seeds/seed_odc.cpio <<'B64'
MDcwNzA3MDAwMDU1MTE3NTA3MTAwNjY0MDAxNzUwMDAxNzUwMDAwMDAxMDAwMDAwMTUyNjMyMDYyNjUwMDAwMDYwMDAwMDAwMDAwNmEudHh0AGhlbGxvCjA3MDcwNzAwMDA1NTExNzUxMDEwMDY2NDAwMTc1MDAwMTc1MDAwMDAwMTAwMDAwMDE1MjYzMjA2MjY1MDAwMDA2MDAwMDAwMDAwMTBiLnR4dAB3b3JsZCEhCjA3MDcwNzAwMDA1NTExNzUxMjEwMDY2NDAwMTc1MDAwMTc1MDAwMDAwMTAwMDAwMDE1MjYzMjA2MjY1MDAwMDEyMDAwMDAwMDAwMDFzdWIvYy50eHQAeDA3MDcwNzAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMTAwMDAwMDAwMDAwMDAwMDAwMDAwMDEzMDAwMDAwMDAwMDBUUkFJTEVSISEhAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
B64
base64 -d > seeds/seed_crc.cpio <<'B64'
MDcwNzAyMDAwMDlGNDcwMDAwODFCNDAwMDAwM0U4MDAwMDAzRTgwMDAwMDAwMTZBQ0QwQ0I1MDAwMDAwMDYwMDAwMDAwMDAwMDAwMDJEMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA2MDAwMDAyMUVhLnR4dABoZWxsbwoAADA3MDcwMjAwMDA5RjQ4MDAwMDgxQjQwMDAwMDNFODAwMDAwM0U4MDAwMDAwMDE2QUNEMENCNTAwMDAwMDA4MDAwMDAwMDAwMDAwMDAyRDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwNjAwMDAwMjc0Yi50eHQAd29ybGQhIQowNzA3MDIwMDAwOUY0QTAwMDA4MUI0MDAwMDAzRTgwMDAwMDNFODAwMDAwMDAxNkFDRDBDQjUwMDAwMDAwMTAwMDAwMDAwMDAwMDAwMkQwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMEEwMDAwMDA3OHN1Yi9jLnR4dAB4AAAAMDcwNzAyMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMTAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwQjAwMDAwMDAwVFJBSUxFUiEhIQAAAAAAAAAAAAAAAAAAAAAAAAAA
B64
base64 -d > seeds/seed_bin.cpio <<'B64'
x3EtAEeftIHoA+gDAQAAAM1qtQwGAAAABgBhLnR4dABoZWxsbwrHcS0ASJ+0gegD6AMBAAAAzWq1DAYAAAAIAGIudHh0AHdvcmxkISEKx3EtAEqftIHoA+gDAQAAAM1qtQwKAAAAAQBzdWIvYy50eHQAeADHcQAAAAAAAAAAAAABAAAAAAAAAAsAAAAAAFRSQUlMRVIhISEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
B64
zip -j $OUT/fuzz_cpio_seed_corpus.zip seeds/* 2>/dev/null || true
