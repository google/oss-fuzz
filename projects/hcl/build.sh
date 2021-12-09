#!/bin/bash -eu
# Copyright 2021 Google Inc.
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

FUZZERS_BASE=$SRC/hcl/hclsyntax/fuzz
FUZZERS_PACKAGE=github.com/hashicorp/hcl/v2/hclsyntax/fuzz
FUZZER_CLASS=Fuzz

for THE_FUZZER in config expr template traversal
do
    THE_FUZZER_NAME="fuzz_"$THE_FUZZER
    compile_go_fuzzer $FUZZERS_PACKAGE/$THE_FUZZER $FUZZER_CLASS $THE_FUZZER_NAME

    OUTDIR=$OUT/$THE_FUZZER_NAME"_seed_corpus"
    mkdir $OUTDIR
    find $FUZZERS_BASE/$THE_FUZZER/corpus -type f | while read FNAME
    do
        SHASUM_NAME=$(shasum "$FNAME" | awk '{print $1}')
        cp "$FNAME" $OUTDIR
    done
    zip -r $OUTDIR".zip" $OUTDIR
    rm -rf $OUTDIR
done