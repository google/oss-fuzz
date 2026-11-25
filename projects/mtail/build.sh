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

# Ensure this pacakge is in go.mod for the compile to work.
go get github.com/AdamKorcz/go-118-fuzz-build/testing

compile_native_go_fuzzer github.com/jaqx0r/mtail/internal/runtime FuzzE2E vm-fuzzer

zip -j $OUT/vm-fuzzer_seed_corpus.zip $SRC/mtail/examples/*.mtail $SRC/mtail/internal/runtime/fuzz/*.mtail

bazel run //cmd/mgen -- --dictionary --out="$OUT/vm-fuzzer.dict"
