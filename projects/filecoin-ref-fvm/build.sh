#!/bin/bash -eu
# Copyright 2021 Google LLC.
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

cd "$SRC"

declare -a PROJECTS=(amt hamt common)
declare -A PROJECT_PATHS=(
	[amt]="ref-fvm/ipld/amt/fuzz"
	[hamt]="ref-fvm/ipld/hamt/fuzz"
	[common]="ref-fvm/testing/common_fuzz/fuzz"
)

export CARGO_TARGET_DIR="$SRC/target"
FUZZ_TARGET_OUTPUT_DIR="$CARGO_TARGET_DIR/x86_64-unknown-linux-gnu/release"


for project in "${PROJECTS[@]}"; do
	pushd "${PROJECT_PATHS[$project]}"

	cargo +nightly fuzz build -O --debug-assertions

	for f in fuzz_targets/*.rs; do
		FUZZ_TARGET_NAME=$(basename "${f%.*}")
		FUZZ_TARGET_LOC="$FUZZ_TARGET_OUTPUT_DIR/$FUZZ_TARGET_NAME"
		FUZZ_OUT_NAME="${project}_${FUZZ_TARGET_NAME}"

		if [ -f "$FUZZ_TARGET_LOC" ]; then
			cp "$FUZZ_TARGET_LOC" "$OUT/$FUZZ_OUT_NAME"
			CORPUS_LOC="$SRC/corpus/corpus/$FUZZ_OUT_NAME"
			if [ -d "$CORPUS_LOC" ]; then
				zip -j "$OUT/${FUZZ_OUT_NAME}_seed_corpus.zip" "$CORPUS_LOC/"*
			fi
		fi
	done

	popd
done

exit 0
