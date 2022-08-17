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

# recompile go from git
(
cd $SRC/goroot/src
export bisect_good=`cat $SRC/gobughunt/good`
export bisect_bad=`cat $SRC/gobughunt/bad`
git log $bisect_good..$bisect_bad --oneline --reverse > gitlog.txt
# take one commit in the range good..bad based on the day of the month
expr '(' `date +"%d"` - 1 ')' '*' `wc -l gitlog.txt | cut -d' ' -f1` / 31 + 1 > logline.txt
cat gitlog.txt | sed -n `cat logline.txt`p | cut -d' ' -f1 | xargs git checkout
./make.bash
)
rm -Rf /root/.go/
mv $SRC/goroot /root/.go

compile_go_fuzzer github.com/google/gonids FuzzParseRule fuzz_parserule

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
