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

export USERCC=$CC
export HOST_CC=$CC
export NOLTO=1

sed 's/gcc-ar/llvm-ar/g' -i sys/static.sh
sys/static.sh || true
cp -r r2-static $OUT/

cp -r ../radare2-fuzz/targets .
export RADARE2_STATIC_BUILD=$OUT/r2-static

export CXXFLAGS="${CXXFLAGS} -I ${RADARE2_STATIC_BUILD}/usr/include/libr/sdb"

cd targets 
make

for target in $(ls *.cc); do
	fuzzer=$(echo $target | cut -d'.' -f1)
	cp $fuzzer $OUT
	cp $SRC/default.options $OUT/$fuzzer.options
done

for seed in $(ls corpora); do
	zip -j corpora/$seed.zip corpora/$seed/*
	cp corpora/$seed.zip $OUT
done
