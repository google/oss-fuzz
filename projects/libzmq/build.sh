#!/bin/bash -eu
# Copyright 2020 Google Inc.
# Copyright 2020 Luca Boccassi <bluca@debian.org>
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

# build project and dependencies
cd "${SRC}/libsodium"
./autogen.sh
./configure --disable-shared
make -j$(nproc) V=1 install DESTDIR=/tmp/zmq_install_dir

cd "${SRC}/libzmq"
./autogen.sh
export LDFLAGS="$(PKG_CONFIG_PATH=/tmp/zmq_install_dir/usr/local/lib/pkgconfig pkg-config --static --libs --define-prefix libsodium)"
export CXXFLAGS="$CXXFLAGS $(PKG_CONFIG_PATH=/tmp/zmq_install_dir/usr/local/lib/pkgconfig pkg-config --static --cflags --define-prefix libsodium)"
./configure --disable-shared --disable-perf --disable-curve-keygen PKG_CONFIG_PATH=/tmp/zmq_install_dir/usr/local/lib/pkgconfig --with-libsodium=yes --with-fuzzing-installdir=fuzzers --with-fuzzing-engine=$LIB_FUZZING_ENGINE
make -j$(nproc) V=1 install DESTDIR=/tmp/zmq_install_dir

cp /tmp/zmq_install_dir/usr/local/fuzzers/* "${OUT}"
