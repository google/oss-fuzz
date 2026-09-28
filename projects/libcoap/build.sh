#!/bin/bash -eu
# Copyright 2018 Google Inc.
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

if [ "$SANITIZER" == "introspector" ]; then
  export WARNING_CFLAGS="${CFLAGS}"
fi

# So the correct architecture specific pkgs are installed.
# These cant be installed in Dockerfile as they want to overwrite the x86_64 versions.
if [ a$ARCHITECTURE = ai386 ] ; then
    NEW_PKGS="pkg-config:i386 libcunit1:i386 libcunit1-dev:i386"
    apt-get install -y ${NEW_PKGS} > /dev/null
    ldconfig
fi

./autogen.sh && ./configure --disable-doxygen --disable-manpages \
                            --with-openssl --enable-tests        \
                            --disable-thread-safe                \
    && make clean > /dev/null && make -j$(nproc)

# Do a sanity check
tests/testdriver 2>&1 | egrep -v passed

# build all fuzzer targets
make -C tests/oss-fuzz -f Makefile.oss-fuzz clean
make -C tests/oss-fuzz -f Makefile.oss-fuzz
