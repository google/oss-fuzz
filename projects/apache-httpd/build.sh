#!/bin/bash -eu
# Copyright 2021 Google LLC
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

unset CPP
INITIAL_CXX=$CXX
unset CXX
export LDFLAGS="-l:libbsd.a"

# Download apr and place in httpd srclib folder. Apr-2.0 includes apr-utils
svn checkout https://svn.apache.org/repos/asf/apr/apr/trunk/ srclib/apr

# Build httpd
./buildconf
./configure --with-included-apr --enable-pool-debug
make -j$( nproc )

static_pcre=($(find /src/pcre2 -name "libpcre2-8.a"))

# Build libapreq2 against the apr we just built.
# APR 2.x merged apr-util, so apu-config no longer exists.
# Provide a shim that delegates to apr-2-config but returns empty for
# --apu-la-file, which apr-2-config does not support.
cat > $SRC/httpd/srclib/apr/apu-2-config <<'EOF'
#!/bin/sh
if [ "$1" = "--apu-la-file" ]; then
  echo ""
else
  exec "$(dirname "$0")/apr-2-config" "$@"
fi
EOF
chmod +x $SRC/httpd/srclib/apr/apu-2-config

cd $SRC/apreq
./buildconf
./configure --with-apache2-src=$SRC/httpd \
            --with-apr-config=$SRC/httpd/srclib/apr/apr-2-config \
            --with-apu-config=$SRC/httpd/srclib/apr/apu-2-config \
            --disable-perl-glue \
            --disable-dependency-tracking \
            APR_MAJOR_VERSION=2
make -C library -j$(nproc)
cd $SRC/httpd

# Build the fuzzers
for fuzzname in utils parse tokenize addr_parse uri request preq; do
  $CC $CFLAGS -c \
    -I$SRC/fuzz-headers/lang/c -I./include -I./os/unix \
    -I./srclib/apr/include -I./srclib/apr-util/include/ \
    -I$SRC/apreq/include \
    $SRC/fuzz_${fuzzname}.c

  $INITIAL_CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_${fuzzname}.o -o $OUT/fuzz_${fuzzname} \
    ./modules.o buildmark.o \
    -Wl,--start-group ./server/.libs/libmain.a \
                      ./modules/core/.libs/libmod_so.a \
                      ./modules/http/.libs/libmod_http.a \
                      ./server/mpm/event/.libs/libevent.a \
                      ./os/unix/.libs/libos.a \
                      ./srclib/apr/.libs/libapr-2.a \
                      $SRC/apreq/library/.libs/libapreq2.a \
    -Wl,--end-group -luuid -lcrypt -lexpat -l:libbsd.a ${static_pcre}
done
