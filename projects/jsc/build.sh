#!/bin/bash -eu
# Copyright 2017 Google Inc.
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
export DEPS_PATH=/src/deps
mkdir $DEPS_PATH

# build ICU for linking statically.
cd $SRC/icu/source
./configure --disable-shared --enable-static --disable-layoutex \
  --disable-tests --disable-samples --with-data-packaging=static --prefix=$DEPS_PATH
make install -j$(nproc)

# Ugly ugly hack to get static linking to work for icu.
cd $DEPS_PATH/lib
ls *.a | xargs -n1 ar x
rm *.a
ar r libicu.a *.{ao,o}
ln -s libicu.a libicudata.a
ln -s libicu.a libicuuc.a
ln -s libicu.a libicui18n.a

export CFLAGS="$CFLAGS -DU_STATIC_IMPLEMENTATION"
export CXXFLAGS="$CXXFLAGS -DU_STATIC_IMPLEMENTATION"
export ICU_ROOT=$DEPS_PATH

cd $SRC/WebKit
Tools/Scripts/build-jsc \
  --debug \
  --jsc-only \
  --cmakeargs="-DENABLE_STATIC_JSC=ON -DUSE_THIN_ARCHIVES=OFF -DWEBKIT_LIBRARIES_DIR=$DEPS_PATH -DWEBKIT_LIBRARIES_INCLUDE_DIR=$DEPS_PATH/include -DWEBKIT_LIBRARIES_LINK_DIR=$DEPS_PATH/lib" \
  --makeargs='-v'

cp WebKitBuild/Debug/bin/jsc $OUT
