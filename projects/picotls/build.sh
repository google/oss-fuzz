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

pushd $SRC/picotls
cmake -DBUILD_FUZZER=ON -DOSS_FUZZ=ON .
make
cp ./fuzz-client-hello $OUT/
cp ./fuzz-server-hello $OUT/

zip -jr $OUT/fuzz-client-hello_seed_corpus.zip $SRC/picotls/fuzz/fuzz-client-hello-corpus
zip -jr $OUT/fuzz-server-hello_seed_corpus.zip $SRC/picotls/fuzz/fuzz-server-hello-corpus
popd
