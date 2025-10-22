#!/bin/bash -eu
# Copyright 2024 Google LLC
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

BUILD=$WORK/meson

rm -rf $BUILD
mkdir $BUILD

meson setup $BUILD \
  -Doss_fuzz=enabled \
  -Db_lundef=false \
  -Ddefault_library=static \
  -Dunicode_support=unistring \
  -Dsystemd_user_services=false \
  -Dintrospection=disabled \
  -Dbuiltin_modules=true \
  -Dvapi=disabled \
  -Ddocs=false \
  -Dtests=false \
  -Dlibsoup3:tests=false \
  -Dlibsoup3:docs=disabled \
  -Dglib:tests=false \
  -Dglib:libmount=disabled \
  -Dglib:oss_fuzz=disabled

ninja -C $BUILD

find $BUILD/fuzzing -maxdepth 1 -executable -type f -exec cp "{}" $OUT \;

find fuzzing -type f -name "*.dict" -exec cp "{}" $OUT \;

for CORPUS in $(find fuzzing -type f -name "*.corpus"); do
  BASENAME=${CORPUS##*/}
  zip $OUT/${BASENAME%%.*}_seed_corpus.zip . -ws -r -i@$CORPUS
done
