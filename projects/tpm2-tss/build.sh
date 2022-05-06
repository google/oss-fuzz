#!/bin/sh
# Copyright 2019 Google Inc.
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

cd $SRC/tpm2-tss/

export LD_LIBRARY_PATH=/usr/local/bin

export GEN_FUZZ=1

./bootstrap
./configure \
  CC=$CC \
  CXX=$CXX \
  --enable-debug \
  --with-fuzzing=ossfuzz \
  --enable-tcti-fuzzing \
  --disable-tcti-device \
  --disable-tcti-mssim \
  --disable-tcti-swtpm \
  --disable-doxygen-doc \
  --disable-shared \
  --disable-fapi \
  --disable-policy

sed -i 's/@DX_RULES@/# @DX_RULES@/g' Makefile
make -j $(nproc) fuzz-targets

for filename in $(ls test/fuzz/*.fuzz); do
  cp -v $filename $OUT/$(echo $(basename $filename .fuzz))
done
