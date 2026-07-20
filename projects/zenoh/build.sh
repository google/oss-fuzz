#!/bin/bash -eu
# Copyright 2026 Google LLC
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

package_seed_corpora() {
    cargo fuzz list | while read -r fuzzer; do
        # Copy fuzzers binaries
        cp "target/x86_64-unknown-linux-gnu/release/${fuzzer}" "$OUT/"

        # OSS-Fuzz automatically detects $OUT/<fuzzer>_seed_corpus.zip and
        # unpacks it into the runtime corpus directory before launching the
        # fuzzer.
        if [ -d "corpus/${fuzzer}" ] && find "corpus/${fuzzer}" -mindepth 1 -print -quit | grep -q .; then
            (
                cd "corpus/${fuzzer}"
                find . -type f | zip -q -@ "$OUT/${fuzzer}_seed_corpus.zip"
            )
        fi
    done
}

run_corpus_generator() {
    local target_dir="$1"
    shift
    local toolchain="$1"
    shift

    # OSS-Fuzz sets sanitizer-specific RUSTFLAGS/CFLAGS/CXXFLAGS for fuzz
    # builds. The corpus generators are regular helper binaries, and building
    # them with those flags can fail when compiling host-side proc-macro
    # dependencies such as `paste`.
    #
    # Build them in a clean environment and use a separate target dir so these
    # unsanitized helper artifacts do not mix with the later `cargo fuzz build`
    # outputs.
    env \
        -u RUSTFLAGS \
        -u CFLAGS \
        -u CXXFLAGS \
        CARGO_TARGET_DIR="${target_dir}" \
        cargo "${toolchain}" run "$@"
}

# Needed for coverage to work.
nightly="+$RUSTUP_TOOLCHAIN"

# Enter the zenoh folder
cd zenoh

# zenoh-codec
cd commons/zenoh-codec/fuzz
run_corpus_generator /tmp/zenoh-codec-corpus "$nightly" --bin gen_all_corpora
cargo "$nightly" fuzz build

package_seed_corpora
cd ../../../

# zenoh-protocol
cd commons/zenoh-protocol/fuzz
run_corpus_generator /tmp/zenoh-protocol-corpus "$nightly" --bin gen_endpoint_corpus
cargo "$nightly" fuzz build

package_seed_corpora
cd ../../../
