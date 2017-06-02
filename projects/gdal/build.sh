#!/bin/bash -eu
# Copyright 2016 Google Inc.
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

# build gdal
cd gdal
export LDFLAGS=${CXXFLAGS}
./configure --without-libtool --with-liblzma --with-expat --with-sqlite3 --with-xerces --with-webp
make clean -s
make -j$(nproc) -s

export EXTRA_LIBS="-Wl,-Bstatic -lwebp -llzma -lexpat -lsqlite3 -lgif -lpng12 -lz -lxerces-c -licuuc -licudata -Wl,-Bdynamic -ldl -lpthread"
./fuzzers/build_google_oss_fuzzers.sh
./fuzzers/build_seed_corpus.sh
