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

cd $SRC/msgpack-ruby

# All C extension files are committed to git — no code generation needed.

# GEM_HOME must be set before any gem install so gems land in $OUT/fuzz-gems,
# which is the only directory available when OSS-Fuzz copies $OUT to run fuzzers.
export GEM_HOME=$OUT/fuzz-gems

gem build msgpack.gemspec
RUZZY_DEBUG=1 gem install --verbose msgpack-*.gem
rsync -avu /install/ruzzy/* $OUT/fuzz-gems

# ASAN_OPTIONS required for Ruby C extension targets.
# Ruby GC, signal stack, and VM frame setup conflict with ASan defaults.
#   allocator_may_return_null=1  — allow malloc to return NULL under memory pressure
#   detect_leaks=0               — Ruby GC manages its own heap; LSan reports false positives
#   use_sigaltstack=0            — Ruby installs its own signal stack, conflicts with ASan
#   detect_stack_use_after_return=0  — Ruby VM frame setup writes into ASan stack redzones
#   detect_stack_use_after_scope=0   — same issue with inlined C functions + rb_funcall
ASAN_OPTS="allocator_may_return_null=1:detect_leaks=0:use_sigaltstack=0:detect_stack_use_after_return=0:detect_stack_use_after_scope=0"

for target in fuzz_unpack fuzz_unpack_stream; do
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

# Seed corpus: msgpack binary test fixtures from the project's own spec suite.
# cases.msg and cases_compact.msg cover all MessagePack types (nil, bool, int,
# float, string, binary, array, map, ext) in both standard and compact formats.
zip -j $OUT/fuzz_unpack_seed_corpus.zip \
    $SRC/msgpack-ruby/spec/cases.msg \
    $SRC/msgpack-ruby/spec/cases_compact.msg
cp $OUT/fuzz_unpack_seed_corpus.zip $OUT/fuzz_unpack_stream_seed_corpus.zip

# Dictionaries: MessagePack type byte markers accelerate coverage discovery
# by helping libFuzzer generate syntactically meaningful byte sequences.
cp $SRC/harnesses/fuzz_unpack.dict $OUT/
cp $SRC/harnesses/fuzz_unpack_stream.dict $OUT/

# Options: raise rss_limit_mb to 4096 because the msgpack binary format allows
# str32/bin32 headers to declare up to 4GB allocations. OSS-Fuzz will report
# this pre-allocation-without-bounds-check as a DoS finding against msgpack-ruby
# (unpacker.c:339 rb_str_buf_new(length) with untrusted length). The higher
# RSS limit lets the fuzzer continue exploring other code paths beyond this known bug.
cp $SRC/harnesses/fuzz_unpack.options $OUT/
cp $SRC/harnesses/fuzz_unpack_stream.options $OUT/
