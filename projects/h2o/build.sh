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

pushd $SRC/h2o
cmake -DBUILD_FUZZER=ON -DOSS_FUZZ=ON -DOPENSSL_USE_STATIC_LIBS=TRUE .
make
cp ./h2o-fuzzer-* $OUT/

zip -jr $OUT/h2o-fuzzer-http1_seed_corpus.zip $SRC/h2o/fuzz/http1-corpus
zip -jr $OUT/h2o-fuzzer-http2_seed_corpus.zip $SRC/h2o/fuzz/http2-corpus
zip -jr $OUT/h2o-fuzzer-http3_seed_corpus.zip $SRC/h2o/fuzz/http3-corpus
zip -jr $OUT/h2o-fuzzer-url_seed_corpus.zip $SRC/h2o/fuzz/url-corpus

cp $SRC/*.options $SRC/h2o/fuzz/*.dict $OUT/
popd
