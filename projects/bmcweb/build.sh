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

cd $SRC/bmcweb

export CFLAGS="${CFLAGS} -fPIC"

# OSS-Fuzz's libc++ does not implement std::move_only_function, so go back to libstdc++
export CXXFLAGS="${CXXFLAGS} -fPIC -stdlib=libstdc++"

CXX_LINK_FLAGS="${CXXFLAGS} -static-libstdc++ -static-libgcc -laudit -lcap"

# Stub systemd.pc – bmcweb only uses it for unit-file install paths.
mkdir -p $WORK/pkgconfig
cat > $WORK/pkgconfig/systemd.pc <<'EOF'
prefix=/usr
systemd_system_unit_dir=${prefix}/lib/systemd/system
Name: systemd
Description: systemd (stub for fuzzing)
Version: 245
EOF
export PKG_CONFIG_PATH="$WORK/pkgconfig:${PKG_CONFIG_PATH:-}"

# Configure with most features disabled
meson setup build \
  -Ddefault_library=static \
  -Dprefer_static=true \
  -Db_lto=false \
  -Dwerror=false \
  -Dtests=disabled \
  -Dfuzz-tests=enabled \
  -Dkvm=disabled \
  -Dvm-websocket=disabled \
  -Drest=disabled \
  -Dhost-serial-socket=disabled \
  -Dstatic-hosting=disabled \
  -Dredfish-bmc-journal=disabled \
  -Dredfish-cpu-log=disabled \
  -Dredfish-dump-log=disabled \
  -Dredfish-dbus-log=disabled \
  -Dredfish-host-logger=disabled \
  -Dinsecure-disable-ssl=enabled \
  -Dinsecure-disable-auth=enabled \
  -Dbmcweb-logging=disabled \
  -Dcpp_args="${CXXFLAGS}" \
  -Dcpp_link_args="${CXX_LINK_FLAGS}" \
  -Dc_args="${CFLAGS}" \
  -Dc_link_args="${CFLAGS}"

# Locate the fuzz targets
FUZZERS=$(meson introspect build --targets |
  jq -r --arg prefix "$PWD/build/" '
    .[]
    | select(.type == "executable" and (.name | endswith("_fuzzer")))
    | .filename[]
    | ltrimstr($prefix)')

if [ -z "$FUZZERS" ]; then
  echo "ERROR: no *_fuzzer executables found; is -Dfuzz-tests=enabled still valid?"
  exit 1
fi

ninja -C build $FUZZERS

for fuzzer in $FUZZERS; do
  cp "build/$fuzzer" "$OUT/$(basename "$fuzzer")"
done
