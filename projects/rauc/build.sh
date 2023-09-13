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

BUILD=$WORK/build

rm -rf $BUILD

# build project

meson setup $BUILD \
  -Ddefault_library=static \
  -Db_lundef=false \
  -Dfuzzing=true \
  -Dglib:libmount=disabled \
  -Dglib:selinux=disabled \
  -Dgpt=disabled \
  -Djson=disabled \
  -Dnetwork=false \
  -Dservice=false \
  -Dstreaming=false \
  --wrap-mode=forcefallback

ninja -C $BUILD

# collect fuzzers and data

find $BUILD/fuzz -maxdepth 1 -executable -type f -exec cp "{}" $OUT \;

find fuzz -type f -name "*.dict" -exec cp "{}" $OUT \;

for CORPUS in $(find fuzz -type f -name "*.corpus"); do
  BASENAME=${CORPUS##*/}
  zip $OUT/${BASENAME%%.*}_seed_corpus.zip . -ws -r -i@$CORPUS
done
