#!/bin/bash -eu
# Copyright 2022 Google LLC
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
./bootstrap
./configure CC="$CC" CFLAGS="$CFLAGS" LDFLAGS="$CFLAGS" --enable-debug --disable-shared
make -j$(nproc)

$CC $CFLAGS -fPIE -pipe -Wall -Wextra -DHAVE_CONFIG_H -DDEBUG -DIXML_HAVE_SCRIPTSUPPORT \
-I./ixml/inc/ -I./upnp/inc -c FuzzIxml.c

$CXX $CFLAGS -fPIE -pipe -o FuzzIxml FuzzIxml.o $LIB_FUZZING_ENGINE ./ixml/.libs/libixml.a

cp FuzzIxml $OUT/FuzzIxml

pushd $SRC/oss-fuzz-bloat/pupnp/
cp FuzzIxml_seed_corpus.zip $OUT/FuzzIxml_seed_corpus.zip
popd
