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
export CXXFLAGS="${CXXFLAGS} -fPIC"

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

# Configure with most features disabled – we only need parsing/utility code.
meson setup build \
  -Ddefault_library=static \
  -Dprefer_static=true \
  -Db_lto=false \
  -Dwerror=false \
  -Dtests=disabled \
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
  -Dcpp_link_args="${CXXFLAGS}" \
  -Dc_args="${CFLAGS}" \
  -Dc_link_args="${CFLAGS}"

# Build as much as possible. The sdbusplus subproject fails to compile but
# all bmcweb object files and other subproject libraries succeed.
ninja -C build -k 0 || true

# Extract compile flags from meson's compile_commands.json so the fuzzer
# sources are compiled with exactly the same flags as bmcweb itself.
COMPILE_FLAGS=$(python3 -c "
import json, shlex, os
builddir = os.path.abspath('build')
with open('build/compile_commands.json') as f:
    for entry in json.load(f):
        if 'json_html_serializer.cpp' in entry['file']:
            args = shlex.split(entry['command'])
            out = []
            i = 1  # skip compiler binary
            while i < len(args):
                a = args[i]
                if a in ('-MF', '-MQ', '-o'):
                    i += 2; continue
                if a in ('-c', '-MD') or a.endswith('.cpp') or a.endswith('.o') or a.endswith('.d'):
                    i += 1; continue
                # Convert relative include paths to absolute
                for prefix in ('-I', '-isystem'):
                    if a.startswith(prefix) and not a.startswith(prefix + '/'):
                        path = a[len(prefix):]
                        a = prefix + os.path.normpath(os.path.join(builddir, path))
                        break
                out.append(a)
                i += 1
            print(' '.join(out))
            break
")

# Find the bmcweb object files produced by ninja that our fuzzers need.
BMCWEB_OBJS=""
for name in boost_asio boost_beast json_html_serializer filter_expr_printer; do
  obj=$(find build -name "*${name}.cpp.o" -print -quit)
  if [ -z "$obj" ]; then
    echo "ERROR: object file for $name not found in build dir"
    exit 1
  fi
  BMCWEB_OBJS="$BMCWEB_OBJS $obj"
done

# Collect all subproject static libraries for linking.
LINK_LIBS=$(find build/subprojects -name "*.a" 2>/dev/null)

# Build each fuzzer.
for fuzzer_src in $SRC/*_fuzzer.cpp; do
  fuzzer_name=$(basename "$fuzzer_src" .cpp)

  $CXX $COMPILE_FLAGS \
    -I$SRC/bmcweb \
    -c "$fuzzer_src" -o "$WORK/${fuzzer_name}.o"

  $CXX $CXXFLAGS -std=c++23 \
    "$WORK/${fuzzer_name}.o" $BMCWEB_OBJS \
    $LIB_FUZZING_ENGINE $LINK_LIBS \
    -lsystemd -lz -lzstd -lssl -lcrypto -latomic -lpam \
    -o "$OUT/${fuzzer_name}"
done
