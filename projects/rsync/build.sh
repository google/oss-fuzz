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

cd $SRC/rsync

# Build rsync with fuzzing-friendly flags
# Use the shipped configure.sh if available, otherwise generate it
if [ -f configure.sh ]; then
    ./configure.sh \
        --disable-md2man \
        --disable-xxhash \
        --disable-zstd \
        --disable-lz4 \
        --with-included-popt \
        CC="$CC" \
        CFLAGS="$CFLAGS" \
        LDFLAGS="$CFLAGS"
else
    autoreconf -i
    ./configure \
        --disable-md2man \
        --disable-xxhash \
        --disable-zstd \
        --disable-lz4 \
        --with-included-popt \
        CC="$CC" \
        CFLAGS="$CFLAGS" \
        LDFLAGS="$CFLAGS"
fi

# Prevent make from trying to regenerate autoconf files
touch configure.sh config.h.in config.h Makefile

make -j$(nproc) || true

# Create a static library from all rsync object files (excluding main.o, cleanup.o, and test tools)
RSYNC_OBJS=$(find . -name '*.o' ! -name 'main.o' ! -name 'cleanup.o' ! -name 'wildtest.o' \
    ! -name 'trimslash.o' ! -name 't_unsafe.o' ! -name 'testrun.o' \
    ! -name 'tls.o' ! -name 'getgroups.o' ! -name 'getfsdev.o' \
    ! -name 't_stub.o' ! -name 'fuzz_*.o' | tr '\n' ' ')

if [ -z "$RSYNC_OBJS" ]; then
    echo "ERROR: No .o files found. Make likely failed."
    exit 1
fi

ar rcs librsync_fuzz.a $RSYNC_OBJS

# Find static libcrypto for linking
LIBCRYPTO=$(find /usr/lib* -name 'libcrypto.a' -print -quit 2>/dev/null || echo "")
if [ -z "$LIBCRYPTO" ]; then
    LIBCRYPTO="-lcrypto"
fi

# Build fuzz_wildmatch — links against just the needed objects
$CC $CFLAGS -I. -I$SRC/rsync -c $SRC/fuzz_wildmatch.c -o fuzz_wildmatch.o
$CXX $CXXFLAGS -I. -o $OUT/fuzz_wildmatch \
    fuzz_wildmatch.o librsync_fuzz.a \
    $LIB_FUZZING_ENGINE $LIBCRYPTO

# Build fuzz_parse_filter
$CC $CFLAGS -I. -I$SRC/rsync -c $SRC/fuzz_parse_filter.c -o fuzz_parse_filter.o
$CXX $CXXFLAGS -I. -o $OUT/fuzz_parse_filter \
    fuzz_parse_filter.o librsync_fuzz.a \
    $LIB_FUZZING_ENGINE $LIBCRYPTO

# Build fuzz_rsyncd_conf
$CC $CFLAGS -I. -I$SRC/rsync -c $SRC/fuzz_rsyncd_conf.c -o fuzz_rsyncd_conf.o
$CXX $CXXFLAGS -I. -o $OUT/fuzz_rsyncd_conf \
    fuzz_rsyncd_conf.o librsync_fuzz.a \
    $LIB_FUZZING_ENGINE $LIBCRYPTO

# Copy dictionaries and options files
cp $SRC/wildmatch.dict $OUT/fuzz_wildmatch.dict
cp $SRC/filter_rules.dict $OUT/fuzz_parse_filter.dict
cp $SRC/rsyncd_conf.dict $OUT/fuzz_rsyncd_conf.dict
cp $SRC/fuzz_parse_filter.options $OUT/fuzz_parse_filter.options
