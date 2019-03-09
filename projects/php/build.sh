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

# build project
./buildconf
./configure --enable-fuzzer --enable-option-checking=fatal --disable-libxml --disable-dom \
	--disable-simplexml --disable-xml --disable-xmlreader --disable-xmlwriter --without-pear \
	--enable-exif --disable-phpdbg --disable-cgi
make
cp sapi/fuzzer/json.dict $OUT/php-fuzz-json.dict
cp sapi/fuzzer/php-fuzz-json $OUT/
cp sapi/fuzzer/php-fuzz-exif $OUT/
for fuzzerName in `ls sapi/fuzzer/corpus`; do
	zip -j $OUT/php-fuzz-${fuzzerName}_seed_corpus.zip sapi/fuzzer/corpus/${fuzzerName}/*
done
