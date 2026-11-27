#!/bin/bash -eu
# Copyright 2023 Google LLC
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

TMP_BUILD_SCRIPT="$(mktemp /tmp/rtpproxy_build.XXXXXX.sh)"
trap 'rm -f "$TMP_BUILD_SCRIPT"' EXIT
cp ./scripts/fuzz/oss-fuzz-build.sh "$TMP_BUILD_SCRIPT"

if [ -f /usr/local/bin/clang-22 ]; then
  sed -i 's/CLANG_VER=18/CLANG_VER=22/g' "$TMP_BUILD_SCRIPT"
fi
sed -i '/\/etc\/apt\/sources\.list/c\  sed -i "s/^Types: deb$/Types: deb deb-src/" /etc/apt/sources.list.d/ubuntu.sources' "$TMP_BUILD_SCRIPT"
sed -i 's/apt-get reinstall -y libssl1\.1/apt-get reinstall -y libssl3t64/' "$TMP_BUILD_SCRIPT"
sed -i 's/dpkg-buildpackage -uc -us/dpkg-buildpackage -b -uc -us/' "$TMP_BUILD_SCRIPT"
sed -i '/if \[ -e "\${PPATH}" \]/i\  if [ "${PKGNAME}" = "libssl-dev" ]; then sed -i "s/^#if !defined(_WIN32)$/#if !defined(_WIN32) \\\&\\\& !defined(time)/" fuzz/client.c fuzz/server.c 2>/dev/null || true; PPATH="/nonexistent"; fi' "$TMP_BUILD_SCRIPT"
sed -i '/if \[ -e "\${PPATH}" \]/i\  if [ "${PKGNAME}" = "libsrtp2-dev" ]; then sed -i "s/--enable-nss/--enable-openssl/" debian/rules; fi' "$TMP_BUILD_SCRIPT"
sed -i '/install_src_pkg libssl-dev openssl/i\    mkdir -p /tmp/orig_libssl && cp -a /lib/x86_64-linux-gnu/libcrypto.so.3 /lib/x86_64-linux-gnu/libssl.so.3 /tmp/orig_libssl/' "$TMP_BUILD_SCRIPT"
sed -i '/install_src_pkg libssl-dev openssl/a\    cp -a /tmp/orig_libssl/libcrypto.so.3 /tmp/orig_libssl/libssl.so.3 /lib/x86_64-linux-gnu/ && rm -rf /tmp/orig_libssl' "$TMP_BUILD_SCRIPT"
sed -i '/-Wl,-Bdynamic -lpthread"/a\  if [ "${SANITIZER}" = "introspector" ]; then LIBSRTP="-L/usr/lib/x86_64-linux-gnu -Wl,-Bstatic -lsrtp2 -lssl -lcrypto -Wl,-Bdynamic $(pkg-config --libs --static libsrtp2 | sed s/-lsrtp2//g) -lpthread"; fi' "$TMP_BUILD_SCRIPT"

bash -ex "$TMP_BUILD_SCRIPT"
