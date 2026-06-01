#!/bin/bash -eu
# Copyright 2026 the Linux Foundation and the OpenSSF Best Practices badge contributors
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
#
# ALTERNATIVE LICENSING NOTICE:
# This file is dual-licensed and is also available
# under the terms of the MIT License.
# You may use this file under the terms of either the Apache 2.0 License
# or the MIT License.
#
# SPDX-License-Identifier: (APACHE-2.0 OR MIT)
#
################################################################################
#
# OSS-Fuzz build script for best-practices-badge.
# Runs inside gcr.io/oss-fuzz-base/base-builder-ruby.
# See https://google.github.io/oss-fuzz/getting-started/new-project-guide/
#
# To test locally:
#   python3 infra/helper.py build_image best-practices-badge
#   python3 infra/helper.py build_fuzzers --sanitizer address best-practices-badge
#   python3 infra/helper.py check_build best-practices-badge
#   python3 infra/helper.py run_fuzzer best-practices-badge fuzz_url_validator

# Install activemodel (+ activesupport chain) for fuzz_url_validator.
# No database or full Rails stack is needed; activemodel is self-contained.

gem install activemodel -v '8.1.3' \
    --install-dir "$GEM_HOME" \
    --verbose

# Install commonmarker for fuzz_markdown_processor.
# The gem ships a pre-built x86_64-linux native extension,
# so no Rust toolchain is needed.
gem install commonmarker -v '2.6.3' \
    --install-dir "$GEM_HOME" \
    --verbose

# Build fuzz targets.  ruzzy-build (provided by base-builder-ruby) copies each
# .rb harness to $OUT and writes a shell wrapper that sets GEM_HOME and invokes
# the ruzzy driver — that wrapper is what OSS-Fuzz/ClusterFuzz actually runs.
ruzzy-build "$SRC/best-practices-badge/script/fuzz_url_validator.rb"
ruzzy-build "$SRC/best-practices-badge/script/fuzz_markdown_processor.rb"

# Seed corpora help the fuzzer reach interesting paths faster.
mkdir -p "$WORK/seed_url"
printf ''                                                           > "$WORK/seed_url/empty"
printf 'https://www.example.com'                                   > "$WORK/seed_url/simple"
printf 'https://github.com/coreinfrastructure/best-practices-badge' > "$WORK/seed_url/long_path"
printf 'https://example.com/foo%%20bar'                            > "$WORK/seed_url/encoded"
printf 'http://example.com:8080/a/b/c'                             > "$WORK/seed_url/port"
printf 'not-a-url'                                                 > "$WORK/seed_url/invalid"
zip -j "$OUT/fuzz_url_validator_seed_corpus.zip" "$WORK/seed_url/"*

mkdir -p "$WORK/seed_md"
printf 'Simple plain text.'                                        > "$WORK/seed_md/plain"
printf 'https://www.example.com'                                   > "$WORK/seed_md/bare_url"
printf 'View more at: https://www.example.com/path?q=1'            > "$WORK/seed_md/prefixed_url"
printf '**bold** and _italic_ text'                                > "$WORK/seed_md/formatting"
printf '[link](https://example.com)'                               > "$WORK/seed_md/link"
printf '| H1 | H2 |\n|----|----|\n| a  | b  |'                    > "$WORK/seed_md/table"
printf '`inline code`'                                             > "$WORK/seed_md/code"
printf '> block quote'                                             > "$WORK/seed_md/blockquote"
printf '<script>alert(1)</script>'                                  > "$WORK/seed_md/xss_attempt"
printf '[x](javascript:alert(1))'                                  > "$WORK/seed_md/bad_protocol"
zip -j "$OUT/fuzz_markdown_processor_seed_corpus.zip" "$WORK/seed_md/"*
