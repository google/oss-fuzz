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

cd $SRC/ruby-json

# All C extension files are committed to git — no code generation needed.

# GEM_HOME must be set before any gem install so gems land in $OUT/fuzz-gems,
# which is the only directory available when OSS-Fuzz copies $OUT to run fuzzers.
export GEM_HOME=$OUT/fuzz-gems

gem build json.gemspec
RUZZY_DEBUG=1 gem install --verbose json-*.gem
rsync -avu /install/ruzzy/* $OUT/fuzz-gems

# ASAN_OPTIONS required for Ruby C extension targets.
# Ruby GC, signal stack, and VM frame setup conflict with ASan defaults.
#   allocator_may_return_null=1  — allow malloc to return NULL under memory pressure
#   detect_leaks=0               — Ruby GC manages its own heap; LSan reports false positives
#   use_sigaltstack=0            — Ruby installs its own signal stack, conflicts with ASan
#   detect_stack_use_after_return=0  — Ruby VM frame setup writes into ASan stack redzones
#   detect_stack_use_after_scope=0   — same issue with inlined C functions + rb_funcall
ASAN_OPTS="allocator_may_return_null=1:detect_leaks=0:use_sigaltstack=0:detect_stack_use_after_return=0:detect_stack_use_after_scope=0"

for target in fuzz_parse fuzz_parse_generate; do
  cp $SRC/harnesses/${target}.rb $OUT/
  cat > $OUT/${target} << WRAPPER
#!/usr/bin/env bash
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=\$(dirname "\$0")
export GEM_HOME=\$this_dir/fuzz-gems
export GEM_PATH=\$this_dir/fuzz-gems
ASAN_OPTIONS="${ASAN_OPTS}" \
  LD_PRELOAD=\$(ruby -e 'require "ruzzy"; print Ruzzy::ASAN_PATH') \
  ruby \$this_dir/${target}.rb "\$@"
WRAPPER
  chmod +x $OUT/${target}
done

# Dictionaries: JSON tokens and structural characters for guided mutation.
cp $SRC/harnesses/fuzz_parse.dict $OUT/
cp $SRC/harnesses/fuzz_parse_generate.dict $OUT/

# Seed corpus: JSON test fixtures from the project's own test suite.
# pass*.json = valid JSON inputs; fail*.json = invalid inputs (error handling paths).
zip -j $OUT/fuzz_parse_seed_corpus.zip \
    $SRC/ruby-json/test/json/fixtures/pass*.json \
    $SRC/ruby-json/test/json/fixtures/fail*.json
cp $OUT/fuzz_parse_seed_corpus.zip $OUT/fuzz_parse_generate_seed_corpus.zip
