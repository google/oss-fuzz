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

cd $SRC/puma

# GEM_HOME must be set before any gem install so gems land in $OUT/fuzz-gems,
# which is the only directory available when OSS-Fuzz copies $OUT to run fuzzers.
export GEM_HOME=$OUT/fuzz-gems

# PUMA_DISABLE_SSL=1 skips mini_ssl.c (OpenSSL TLS wrapper) — we target only the
# HTTP/1.1 request parser (http11_parser.c, Ragel-generated state machine).
# The Ragel-generated http11_parser.c is already committed; no Ragel needed.
#
# Remove the nio4r runtime dependency from the gemspec: we only use
# Puma::HttpParser (the C extension), which has no dependency on nio4r's
# event loop. Without this, RubyGems raises MissingSpecError on gem activation.
sed -i '/nio4r/d' puma.gemspec

PUMA_DISABLE_SSL=1 gem build puma.gemspec
RUZZY_DEBUG=1 gem install --verbose puma-*.gem
rsync -avu /install/ruzzy/* $OUT/fuzz-gems

# ASAN_OPTIONS required for Ruby C extension targets.
ASAN_OPTS="allocator_may_return_null=1:detect_leaks=0:use_sigaltstack=0:detect_stack_use_after_return=0:detect_stack_use_after_scope=0"

for target in fuzz_http_parser; do
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

# Dictionary: HTTP tokens and CVE-relevant sequences.
cp $SRC/harnesses/fuzz_http_parser.dict $OUT/

# Seed corpus: representative HTTP/1.1 requests covering common paths and
# historical CVE patterns (request smuggling, chunked encoding, LF injection).
mkdir -p /tmp/corpus

# Valid GET request
printf 'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n' \
    > /tmp/corpus/get_basic.txt

# POST with Content-Length
printf 'POST /submit HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nhello' \
    > /tmp/corpus/post_content_length.txt

# Multiple headers
printf 'GET /path?query=1 HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\nAccept: */*\r\nUser-Agent: fuzzer\r\n\r\n' \
    > /tmp/corpus/get_headers.txt

# Transfer-Encoding: chunked (CVE-2023-40175 class)
printf 'POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n' \
    > /tmp/corpus/post_chunked.txt

# OPTIONS / HEAD
printf 'OPTIONS * HTTP/1.1\r\nHost: localhost\r\n\r\n' \
    > /tmp/corpus/options.txt
printf 'HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n' \
    > /tmp/corpus/head.txt

# Partial request (incomplete — exercises incremental parse path)
printf 'GET / HTTP/1.1\r\nHost: loc' \
    > /tmp/corpus/partial.txt

# Zero Content-Length (CVE-2023-40175 class)
printf 'POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n' \
    > /tmp/corpus/zero_content_length.txt

zip -j $OUT/fuzz_http_parser_seed_corpus.zip /tmp/corpus/*.txt
