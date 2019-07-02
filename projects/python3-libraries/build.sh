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

export ASAN_OPTIONS="detect_leaks=0"

export CPYTHON_INSTALL_PATH=$OUT/cpython-install
rm -rf $CPYTHON_INSTALL_PATH
mkdir $CPYTHON_INSTALL_PATH

cd $SRC/cpython-fuzzing
git checkout fuzzing
LDFLAGS=$CFLAGS ./configure --prefix=$CPYTHON_INSTALL_PATH
make -j$(nproc)
make install

cd $SRC/python-library-fuzzers
make

cp $SRC/python-library-fuzzers/fuzzer-html $OUT/
cp $SRC/python-library-fuzzers/html.py $OUT/
zip -j $OUT/fuzzer-html_seed_corpus.zip corp-html/*

cp $SRC/python-library-fuzzers/fuzzer-email $OUT/
cp $SRC/python-library-fuzzers/email.py $OUT/
zip -j $OUT/fuzzer-email_seed_corpus.zip corp-email/*

cp $SRC/python-library-fuzzers/fuzzer-httpclient $OUT/
cp $SRC/python-library-fuzzers/httpclient.py $OUT/
zip -j $OUT/fuzzer-httpclient_seed_corpus.zip corp-httpclient/*

cp $SRC/python-library-fuzzers/fuzzer-json $OUT/
cp $SRC/python-library-fuzzers/json.py $OUT/
zip -j $OUT/fuzzer-json_seed_corpus.zip corp-json/*

