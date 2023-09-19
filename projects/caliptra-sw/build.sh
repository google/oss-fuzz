#!/bin/bash -eu
# Copyright 2023 Google LLC
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

build_one_target () {
	if [[ $# -lt 5 ]]; then
		echo "[caliptra-sw] Error: Invalid arguments!"
		return
	fi

	local name=$1
	local fuzz_target_path=$2
	local fuzz_target_name=$3
	local fuzzer_features=$4
	local fuzzer_sanitiser=$5

	pushd ${fuzz_target_path}
	cargo +nightly-2023-04-15 fuzz build \
		--features libfuzzer-sys,${fuzzer_features} \
		-s ${fuzzer_sanitiser} \
		${fuzz_target_name}
	cp ${CARGO_TARGET_DIR}/x86_64-unknown-linux-gnu/release/${fuzz_target_name} $OUT/${name}
	popd
}

# Fuzzing targets are excluded from workspace, unify build directory as performance optimisation
export CARGO_TARGET_DIR=$(mktemp -d)

# Build Image Verifier seed corpus
mkdir -p image/verify/fuzz/common_corpus
for x in $(seq 01 04); do
	RUSTFLAGS= CFLAGS= CXXFLAGS= cargo run -j$(nproc) --manifest-path=builder/Cargo.toml --release --bin image -- --fake-rom /dev/null --fw image/verify/fuzz/common_corpus/${x}
	cargo clean
done

build_one_target "dpe" dpe/dpe/fuzz fuzz_target_1 "" address
zip $OUT/dpe_seed_corpus.zip dpe/dpe/fuzz/common_corpus/*
build_one_target "image_verify" image/verify/fuzz fuzz_target_coldreset "struct-aware" address
zip $OUT/image_verify_seed_corpus.zip image/verify/fuzz/common_corpus/*
build_one_target "lms" drivers/fuzz fuzz_target_lms "struct-aware" address
zip $OUT/lms_seed_corpus.zip drivers/fuzz/common_corpus/*
CFLAGS= CXXFLAGS= build_one_target "x509" x509/fuzz fuzz_target_1 "" address
zip $OUT/x509_seed_corpus.zip x509/fuzz/common_corpus/*

cp $SRC/*.options $OUT/
