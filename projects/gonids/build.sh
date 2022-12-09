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

compile_go_fuzzer github.com/google/gonids FuzzParseRule fuzz_parserule

# output it in logs to compare with local builds for https://github.com/golang/go/issues/49075
base64 $OUT/fuzz_parserule

cd $SRC
unzip emerging.rules.zip
cd rules
i=0
mkdir corpus
# quit output for commands
set +x
cat *.rules | while read l; do echo $l > corpus/$i.rule; i=$((i+1)); done
set -x
zip -q -r $OUT/fuzz_parserule_seed_corpus.zip corpus

# use different GODEBUG env variables for https://github.com/golang/go/issues/49075
cp $SRC/gobughunt/fuzz_parserule.options $OUT/
