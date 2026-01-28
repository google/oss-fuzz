#!/bin/bash -eu
# Copyright 2025 Google LLC
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

BINARY=$SRC/mhd2/src/mhd2/.libs/libmicrohttpd2.a

# Build libmicrohttpd
git pull
./autogen.sh
# Compile MHD with the SAME compiler used later.
export CC=$CXX
# Enable most features, force specific TLS library, and disable symbol hiding
./configure \
    --enable-dauth \
    --enable-md5=builtin \
    --enable-sha256=builtin \
    --enable-sha512-256=builtin \
    --enable-bauth \
    --enable-upgrade \
    --enable-https \
    --without-openssl \
    --enable-messages \
    --disable-examples \
    mhd_cv_cc_attr_visibility_default="no" \
    mhd_cv_cc_attr_visibility_internal="no" \
    mhd_cv_cc_attr_visibility_hidden="no"
ASAN_OPTIONS=detect_leaks=0 make -j$(nproc)
make install

# Compile fuzzer
FUZZERS="fuzz_response fuzz_daemon fuzz_mhd2 fuzz_str fuzz_crypto_int fuzz_libinfo fuzz_connection fuzz_daemon_connection"

for fuzzer in $FUZZERS; do
  extra_src=""
  case "$fuzzer" in
    fuzz_response|fuzz_daemon)
      extra_src="$SRC/mhd_helper.cpp"
      ;;
  esac
  case "$fuzzer" in
    fuzz_connection|fuzz_daemon_connection)
      extra_src="$SRC/connection_helper.cpp"
      ;;
  esac

  $CXX $CXXFLAGS -DHAVE_CONFIG_H "$SRC/$fuzzer.cpp" $extra_src \
    -Wno-unused-parameter -Wno-unused-value -pthread \
    -I"$SRC" -I"$SRC/mhd2/src/mhd2" -I"$SRC/mhd2/src/include" \
    -I"$SRC/mhd2/src/incl_priv" -I"$SRC/mhd2/src/incl_priv/config" \
    $LIB_FUZZING_ENGINE "$BINARY" -lgnutls -o "$OUT/$fuzzer"
done

# Rebuild the binary for external crypto with libgcrypt
./autogen.sh
./configure \
    --enable-md5=tlslib \
    --enable-sha256=tlslib \
    --enable-sha512-256=builtin \
    --without-openssl \
    --disable-examples \
    mhd_cv_cc_attr_visibility_default="no" \
    mhd_cv_cc_attr_visibility_internal="no" \
    mhd_cv_cc_attr_visibility_hidden="no"
make clean
make -j$(nproc)
make install

$CXX $CXXFLAGS $SRC/fuzz_crypto_ext.cpp -DHAVE_CONFIG_H \
  -Wno-unused-parameter -Wno-unused-value -I$SRC/mhd2/src/mhd2 \
  -I$SRC/mhd2/src/include -I$SRC/mhd2/src/incl_priv \
  -I$SRC/mhd2/src/incl_priv/config $LIB_FUZZING_ENGINE $BINARY \
  -lgnutls -o $OUT/fuzz_crypto_ext

cp $SRC/default.options $OUT/fuzz_daemon.options
cp $SRC/*.dict $OUT/
