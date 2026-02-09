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

cd $SRC/openldap

# Configure OpenLDAP with minimal options
./configure \
    --disable-slapd \
    --disable-backends \
    --disable-overlays \
    --disable-dynamic \
    --enable-static \
    --without-cyrus-sasl \
    --with-tls=no \
    CC="$CC" CFLAGS="$CFLAGS" CPPFLAGS="$CFLAGS" LDFLAGS="$CFLAGS"

# Build just the libraries we need
cd libraries
make -j$(nproc) depend || true
make -j$(nproc) || true
cd ..

LDAP_INCLUDES="-I$SRC/openldap/include -I$SRC/openldap/libraries/libldap -I$SRC/openldap/libraries/liblber"
LDAP_LIBS="$SRC/openldap/libraries/libldap/.libs/libldap.a $SRC/openldap/libraries/liblber/.libs/liblber.a"

# Check if the libraries were built
if [ ! -f "$SRC/openldap/libraries/libldap/.libs/libldap.a" ]; then
    # Try without .libs
    LDAP_LIBS="$SRC/openldap/libraries/libldap/libldap.a $SRC/openldap/libraries/liblber/liblber.a"
    if [ ! -f "$SRC/openldap/libraries/libldap/libldap.a" ]; then
        echo "Warning: libldap not built, building standalone fuzzers only"
        LDAP_LIBS=""
    fi
fi

# === fuzz_ldap_dn: Distinguished Name parsing ===
$CC $CFLAGS $LDAP_INCLUDES \
    -c $SRC/fuzz_ldap_dn.c -o $SRC/fuzz_ldap_dn.o

if [ -n "$LDAP_LIBS" ]; then
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
        $SRC/fuzz_ldap_dn.o \
        $LDAP_LIBS \
        -lssl -lcrypto -lresolv \
        -o $OUT/fuzz_ldap_dn || \
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
        $SRC/fuzz_ldap_dn.o \
        $LDAP_LIBS \
        -o $OUT/fuzz_ldap_dn || \
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
        $SRC/fuzz_ldap_dn.o \
        -o $OUT/fuzz_ldap_dn
else
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
        $SRC/fuzz_ldap_dn.o \
        -o $OUT/fuzz_ldap_dn
fi

cp $SRC/fuzz_ldap_dn.dict $OUT/ || true

# === fuzz_ldap_filter: LDAP search filter parsing ===
$CC $CFLAGS $LDAP_INCLUDES \
    -c $SRC/fuzz_ldap_filter.c -o $SRC/fuzz_ldap_filter.o

if [ -n "$LDAP_LIBS" ]; then
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
        $SRC/fuzz_ldap_filter.o \
        $LDAP_LIBS \
        -lssl -lcrypto -lresolv \
        -o $OUT/fuzz_ldap_filter || \
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
        $SRC/fuzz_ldap_filter.o \
        $LDAP_LIBS \
        -o $OUT/fuzz_ldap_filter || \
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
        $SRC/fuzz_ldap_filter.o \
        -o $OUT/fuzz_ldap_filter
else
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
        $SRC/fuzz_ldap_filter.o \
        -o $OUT/fuzz_ldap_filter
fi

cp $SRC/fuzz_ldap_filter.dict $OUT/ || true

# === fuzz_ldap_url: LDAP URL parsing ===
$CC $CFLAGS $LDAP_INCLUDES \
    -c $SRC/fuzz_ldap_url.c -o $SRC/fuzz_ldap_url.o

if [ -n "$LDAP_LIBS" ]; then
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
        $SRC/fuzz_ldap_url.o \
        $LDAP_LIBS \
        -lssl -lcrypto -lresolv \
        -o $OUT/fuzz_ldap_url || \
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
        $SRC/fuzz_ldap_url.o \
        $LDAP_LIBS \
        -o $OUT/fuzz_ldap_url || \
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
        $SRC/fuzz_ldap_url.o \
        -o $OUT/fuzz_ldap_url
else
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
        $SRC/fuzz_ldap_url.o \
        -o $OUT/fuzz_ldap_url
fi

cp $SRC/fuzz_ldap_url.dict $OUT/ || true
