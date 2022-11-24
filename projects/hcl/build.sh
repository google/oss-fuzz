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

FUZZERS_PACKAGE=github.com/hashicorp/hcl/v2
go get github.com/AdamKorcz/go-118-fuzz-build/testing

compile_native_go_fuzzer $FUZZERS_PACKAGE/hclsyntax/fuzz FuzzParseTemplate FuzzParseTemplate
compile_native_go_fuzzer $FUZZERS_PACKAGE/hclsyntax/fuzz FuzzParseTraversalAbs FuzzParseTraversalAbs
compile_native_go_fuzzer $FUZZERS_PACKAGE/hclsyntax/fuzz FuzzParseExpression FuzzParseExpression
compile_native_go_fuzzer $FUZZERS_PACKAGE/hclsyntax/fuzz FuzzParseConfig FuzzHclSyntaxParseConfig
compile_native_go_fuzzer $FUZZERS_PACKAGE/json/fuzz FuzzParse FuzzParse
compile_native_go_fuzzer $FUZZERS_PACKAGE/hclwrite/fuzz FuzzParseConfig FuzzHclWriteParseConfig

zip $OUT/FuzzParseTemplate_seed_corpus.zip $SRC/hcl/hclsyntax/fuzz/testdata/fuzz/FuzzParseTemplate/*
zip $OUT/FuzzParseTraversalAbs_seed_corpus.zip $SRC/hcl/hclsyntax/fuzz/testdata/fuzz/FuzzParseTraversalAbs/*
zip $OUT/FuzzParseTemplate_seed_corpus.zip $SRC/hcl/hclsyntax/fuzz/testdata/fuzz/FuzzParseTemplate/*
zip $OUT/FuzzParseExpression_seed_corpus.zip $SRC/hcl/hclsyntax/fuzz/testdata/fuzz/FuzzParseExpression/*
zip $OUT/FuzzParse_seed_corpus.zip $SRC/hcl/json/fuzz/testdata/fuzz/FuzzParse/*
zip $OUT/FuzzHclWriteParseConfig_seed_corpus.zip $SRC/hcl/hclsyntax/fuzz/testdata/fuzz/FuzzParseConfig/*
