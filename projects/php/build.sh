#!/bin/bash -eu
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

mkdir -p $OUT/lib/
cp sapi/fuzzer/json.dict $OUT/php-fuzz-json.dict
cp /usr/lib/x86_64-linux-gnu/libonig.so.5 $OUT/lib/
# build project
./buildconf
./configure --enable-fuzzer --enable-option-checking=fatal --without-libxml --disable-dom \
	--disable-simplexml --disable-xml --disable-xmlreader --disable-xmlwriter --without-pear \
	--enable-exif --disable-phpdbg --disable-cgi --enable-mbstring --with-pic
make -j$(nproc)

# Generate dictionary for unserialize fuzzer
sapi/cli/php sapi/fuzzer/generate_unserialize_dict.php
cp sapi/fuzzer/dict/unserialize $OUT/php-fuzz-unserialize.dict

FUZZERS="php-fuzz-json php-fuzz-exif php-fuzz-mbstring php-fuzz-unserialize"
for fuzzerName in $FUZZERS; do
	cp sapi/fuzzer/$fuzzerName $OUT/
	# for loading missing libs like libonig
	chrpath -r '$ORIGIN/lib' $OUT/$fuzzerName
done
# copy corpora from source
for fuzzerName in `ls sapi/fuzzer/corpus`; do
	zip -j $OUT/php-fuzz-${fuzzerName}_seed_corpus.zip sapi/fuzzer/corpus/${fuzzerName}/*
done

