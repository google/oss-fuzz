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

# All fuzz targets share a single gem directory under $OUT so that every
# gem (oj + ruzzy + dependencies) is available at runtime after check_build
# copies the $OUT tree to a temporary location.
export GEM_HOME=$OUT/fuzz-gems

cd $SRC/oj-ruby

# Install runtime dependencies into GEM_HOME
gem install bigdecimal --no-document
gem install ostruct --no-document

# Build from source so extconf.rb picks up CFLAGS/CXXFLAGS (set in Dockerfile)
# which include -fsanitize=fuzzer-no-link for coverage instrumentation.
gem build oj.gemspec
RUZZY_DEBUG=1 gem install --verbose oj-*.gem

# Merge ruzzy's shared library and support files into the same GEM_HOME
rsync -avu /install/ruzzy/* $OUT/fuzz-gems

# ASAN_OPTIONS used by all wrapper scripts:
#   allocator_may_return_null=1    — allow malloc to return NULL under memory pressure
#   detect_leaks=0                 — Ruby GC manages its own heap; LeakSanitizer fires false positives
#   use_sigaltstack=0              — Ruby installs its own signal stack; conflicts with ASan
#   detect_stack_use_after_return=0  \
#   detect_stack_use_after_scope=0   / Ruby VM frame setup writes into ASan stack redzones around
#                                      inlined functions, producing non-reproducible
#                                      stack-buffer-overflow reports. These are false positives
#                                      caused by the Ruby interpreter's stack management.
ASAN_OPTS="allocator_may_return_null=1:detect_leaks=0:use_sigaltstack=0:detect_stack_use_after_return=0:detect_stack_use_after_scope=0"

# ---- fuzz_load ---------------------------------------------------------------

cp $SRC/harnesses/fuzz_load.rb $OUT/

cat > $OUT/fuzz_load << WRAPPER
#!/usr/bin/env bash
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=\$(dirname "\$0")
export GEM_HOME=\$this_dir/fuzz-gems
export GEM_PATH=\$this_dir/fuzz-gems
ASAN_OPTIONS="${ASAN_OPTS}" \
  LD_PRELOAD=\$(ruby -e 'require "ruzzy"; print Ruzzy::ASAN_PATH') \
  ruby \$this_dir/fuzz_load.rb "\$@"
WRAPPER

chmod +x $OUT/fuzz_load

# ---- fuzz_saj_parse ----------------------------------------------------------

cp $SRC/harnesses/fuzz_saj_parse.rb $OUT/

cat > $OUT/fuzz_saj_parse << WRAPPER
#!/usr/bin/env bash
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=\$(dirname "\$0")
export GEM_HOME=\$this_dir/fuzz-gems
export GEM_PATH=\$this_dir/fuzz-gems
ASAN_OPTIONS="${ASAN_OPTS}" \
  LD_PRELOAD=\$(ruby -e 'require "ruzzy"; print Ruzzy::ASAN_PATH') \
  ruby \$this_dir/fuzz_saj_parse.rb "\$@"
WRAPPER

chmod +x $OUT/fuzz_saj_parse

# ---- fuzz_parser -------------------------------------------------------------

cp $SRC/harnesses/fuzz_parser.rb $OUT/

cat > $OUT/fuzz_parser << WRAPPER
#!/usr/bin/env bash
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=\$(dirname "\$0")
export GEM_HOME=\$this_dir/fuzz-gems
export GEM_PATH=\$this_dir/fuzz-gems
ASAN_OPTIONS="${ASAN_OPTS}" \
  LD_PRELOAD=\$(ruby -e 'require "ruzzy"; print Ruzzy::ASAN_PATH') \
  ruby \$this_dir/fuzz_parser.rb "\$@"
WRAPPER

chmod +x $OUT/fuzz_parser

# ---- seed corpus -------------------------------------------------------------

# Use upstream JSON fixtures as seed inputs.
# pass*.json — valid JSON covering common structures; bootstrap coverage quickly.
# fail*.json — malformed JSON that exercises error-handling paths in the C code.
zip -j $OUT/fuzz_load_seed_corpus.zip \
    $SRC/oj-ruby/test/json_gem/fixtures/pass*.json \
    $SRC/oj-ruby/test/json_gem/fixtures/fail*.json \
    $SRC/oj-ruby/test/sample_obj.json

cp $OUT/fuzz_load_seed_corpus.zip $OUT/fuzz_saj_parse_seed_corpus.zip
cp $OUT/fuzz_load_seed_corpus.zip $OUT/fuzz_parser_seed_corpus.zip
