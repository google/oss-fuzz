#!/bin/bash -eu
# Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
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

cd "$SRC/arm-ffa"

# The flags set by OSS-Fuzz can cause build errors with host-side proc-macro
# dependencies, so we unset them for this build only
env -u CFLAGS -u CXXFLAGS -u RUSTFLAGS cargo run --bin fuzzer_corpus

cargo fuzz build -O

triple=$(rustc -vV | sed -n 's/^host: //p')
for fuzzer in $(cargo fuzz list); do
	cp "fuzz/target/$triple/release/$fuzzer" "$OUT/"
	[ -d "fuzz/corpus/$fuzzer" ] &&
		zip -j "$OUT/${fuzzer}_seed_corpus.zip" "fuzz/corpus/$fuzzer"/*
done
