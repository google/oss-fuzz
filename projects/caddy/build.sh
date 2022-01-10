#!/bin/bash -eu
# Copyright 2021 Google LLC
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

# We move the caddy folder in here rather than the Dockerfile to make CI work.
# See here for the failure that triggered this: https://github.com/caddyserver/caddy/pull/4449
mkdir -p $GOPATH/src/github.com/caddyserver/caddy/
mv $SRC/caddy $GOPATH/src/github.com/caddyserver/caddy/v2
cd "$GOPATH"/src/github.com/caddyserver/caddy/v2

find . -name '*_fuzz.go' | while read -r target
do
# Arguments are :
#     path of the package with the fuzz target
#     name of the fuzz function
#     name of the fuzzer to be built
#     optional tag to be used by go build and such

    fuzzed_func=$(grep -o "Fuzz[a-zA-Z]\+" "$target")
    fuzzer_name=$(echo "$fuzzed_func" | sed -E 's/([A-Z])/-\L\1/g' | sed 's/^-//')
    # find the relative directory and remove the first `.` (`./` is removed for root)
    target_dir=$(dirname "$target"); target_dir="${target_dir//.}";
    target_corpus_name="${fuzzer_name}_seed_corpus.zip"

    curl -s -f -O "https://raw.githubusercontent.com/caddyserver/caddy/fuzz-seed-corpus/${target_corpus_name}" || true
    compile_go_fuzzer github.com/caddyserver/caddy/v2"$target_dir" "$fuzzed_func" "$fuzzer_name" gofuzz
done
