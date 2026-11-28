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

# Build OpenSSL with MSan so Poco does not link uninstrumented system libssl/libcrypto.
if [ "$SANITIZER" = "memory" ] && [ "$ARCHITECTURE" = "x86_64" ]; then
  OPENSSL_PREFIX="$WORK/openssl-msan"
  OPENSSL_BUILD="$WORK/openssl-build"
  rm -rf "$OPENSSL_BUILD" "$OPENSSL_PREFIX"
  mkdir -p "$OPENSSL_BUILD"
  (
    cd "$OPENSSL_BUILD"
    CC="$CC" CFLAGS="$CFLAGS -fPIC" "$SRC/openssl/Configure" linux-x86_64 \
      --prefix="$OPENSSL_PREFIX" --libdir=lib no-asm no-shared no-tests
    make -j"$(nproc)" build_libs
    make install_dev
  )
  export OPENSSL_ROOT_DIR="$OPENSSL_PREFIX"
fi

bash -eu "$SRC/poco/build/script/oss-fuzz-build.sh"
