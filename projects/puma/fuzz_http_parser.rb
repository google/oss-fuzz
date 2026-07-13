# frozen_string_literal: true
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

# Exercises ext/puma_http11/http11_parser.c (Ragel-generated, 1057 LOC)
# via Puma::HttpParser#execute — the main HTTP/1.1 request header parser.
#
# Historical CVEs in this parser:
#   CVE-2022-24790 (CRITICAL) — request smuggling, RFC7230 mismatch
#   CVE-2023-40175 (CRITICAL) — request smuggling via chunked + zero Content-Length
#   CVE-2021-41136 (LOW)      — request smuggling via LF in header values
#   CVE-2020-5247  (HIGH)     — response splitting via CR/LF in headers
#   CVE-2024-45614 (MEDIUM)   — header value clobbering

require 'ruzzy'
require 'puma/puma_http11'

PARSE_FNS = [
  # Standard parse from offset 0 — main code path
  ->(str) {
    Puma::HttpParser.new.execute({}, str, 0)
  },
  # Resume parse after partial read — exercises incremental parsing path
  ->(str) {
    return Puma::HttpParser.new.execute({}, str, 0) if str.bytesize < 2

    parser = Puma::HttpParser.new
    req = {}
    split = str.bytesize / 2
    nread = parser.execute(req, str.byteslice(0, split), 0)
    parser.execute(req, str, nread) unless parser.finished?
  },
].freeze

test_one_input = lambda do |data|
  return 0 if data.empty?
  str = data.to_s
  fn = PARSE_FNS[data.length % PARSE_FNS.size]
  begin
    fn.call(str)
  rescue Puma::HttpParserError
  rescue SystemStackError
  rescue EncodingError, ArgumentError, TypeError
  rescue StandardError
  end
  0
end

Ruzzy.fuzz(test_one_input)
