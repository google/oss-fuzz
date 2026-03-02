#!/bin/bash -eu
# Copyright 2020 Google Inc.
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

# go-118-fuzz-build_v2 overlays $GOROOT/src/testing/fuzz.go. When Go
# downloads a newer toolchain to satisfy a go.work/go.mod requirement,
# GOROOT falls under GOMODCACHE whose files Go refuses to overlay. To
# work around this, copy the downloaded toolchain to a writable temp
# dir, prepend it to PATH, and pin GOTOOLCHAIN=local so the copied
# go binary (which IS the required version) is used directly.
goroot=$(go env GOROOT)
gomodcache=$(go env GOMODCACHE)
if [[ "$goroot" == "$gomodcache"* ]]; then
  tmp_go=$(mktemp -d)
  cp -r "$goroot/." "$tmp_go"
  export GOROOT="$tmp_go"
  export PATH="$tmp_go/bin:$PATH"
  export GOTOOLCHAIN=local
fi

compile_native_go_fuzzer_v2 github.com/prometheus/prometheus/util/fuzzing FuzzParseMetricText fuzzParseMetricText
compile_native_go_fuzzer_v2 github.com/prometheus/prometheus/util/fuzzing FuzzParseOpenMetric fuzzParseOpenMetric
compile_native_go_fuzzer_v2 github.com/prometheus/prometheus/util/fuzzing FuzzParseMetricSelector fuzzParseMetricSelector
compile_native_go_fuzzer_v2 github.com/prometheus/prometheus/util/fuzzing FuzzParseExpr fuzzParseExpr

/root/.go/bin/go generate -tags fuzzing ./util/fuzzing/corpus_gen
mv util/fuzzing/fuzzParseExpr_seed_corpus.zip $OUT/
mv util/fuzzing/fuzzParseMetricSelector_seed_corpus.zip $OUT/
mv util/fuzzing/fuzzParseMetricText_seed_corpus.zip $OUT/
mv util/fuzzing/fuzzParseOpenMetric_seed_corpus.zip $OUT/
