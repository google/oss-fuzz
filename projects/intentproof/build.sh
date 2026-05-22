#!/bin/bash -eu
# Copyright 2026 IntentProof contributors
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

TOOLS_SRC="${SRC}/intentproof-tools"
SPEC_SRC="${SRC}/intentproof-spec"
CORE_SRC="${SRC}/intentproof-core"

export INTENTPROOF_SPEC_DIR="${SPEC_SRC}"

go get github.com/AdamKorcz/go-118-fuzz-build/testing

pack_seed_corpus() {
  local fuzzer_name="$1"
  local corpus_dir="$2"
  if [[ ! -d "${corpus_dir}" ]]; then
    return 0
  fi
  shopt -s nullglob
  local files=("${corpus_dir}"/*)
  shopt -u nullglob
  if (( ${#files[@]} == 0 )); then
    return 0
  fi
  (cd "${corpus_dir}" && zip -j "${OUT}/${fuzzer_name}_seed_corpus.zip" ./*)
}

cd "${TOOLS_SRC}"
export GOWORK=off

compile_native_go_fuzzer github.com/intentproof/intentproof-tools/pkg/canon FuzzMarshalRaw fuzz_marshal_raw
pack_seed_corpus fuzz_marshal_raw "${SPEC_SRC}/golden/fuzz-corpora/canon"

compile_native_go_fuzzer github.com/intentproof/intentproof-tools/pkg/verifier FuzzVerify fuzz_verify

compile_native_go_fuzzer github.com/intentproof/intentproof-tools/pkg/bundle FuzzBundleVerify fuzz_bundle_verify
pack_seed_corpus fuzz_bundle_verify "${SPEC_SRC}/golden/fuzz-corpora/bundle"

compile_native_go_fuzzer github.com/intentproof/intentproof-tools/pkg/policy FuzzCompile fuzz_compile
pack_seed_corpus fuzz_compile "${SPEC_SRC}/golden/fuzz-corpora/policy"

cat > "${SRC}/go.work" <<EOF
go 1.25.10

use (
	./intentproof-tools
	./intentproof-core
)
EOF

cd "${CORE_SRC}"
export GOWORK="${SRC}/go.work"

compile_native_go_fuzzer github.com/intentproof/intentproof-core/pkg/ingest FuzzParseExecutionEvent fuzz_parse_execution_event
pack_seed_corpus fuzz_parse_execution_event "${SPEC_SRC}/golden/fuzz-corpora/ingest"
