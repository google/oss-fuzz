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

require 'ruzzy'
require 'json'

# Exercises ext/json/ext/generator/generator.c (1978 LOC) + vendor/fpconv.c
# and vendor/ryu.h via:
#   1. Parse-generate round-trips (exercises both parser.c and generator.c)
#   2. Direct generation from input bytes (exercises string escaping + float serialization)
GENERATE_FNS = [
  # Round-trip: parse → generate (main generator path, all types)
  ->(str) {
    obj = JSON.parse(str)
    JSON.generate(obj)
  },
  # Round-trip with ascii_only: non-ASCII chars → \uXXXX (different string encoding path)
  ->(str) {
    obj = JSON.parse(str)
    JSON.generate(obj, ascii_only: true)
  },
  # Round-trip with script_safe: escapes </script>, <!-- sequences in strings
  ->(str) {
    obj = JSON.parse(str)
    JSON.generate(obj, script_safe: true)
  },
  # Direct: generate array of raw bytes (exercises integer serialization via jeaiii-ltoa.h)
  ->(str) { JSON.generate(str.bytes) },
  # Direct: generate the string itself (exercises string escaping, control char handling)
  ->(str) { JSON.generate(str) },
].freeze

test_one_input = lambda do |data|
  return 0 if data.empty?
  str = data.to_s
  fn = GENERATE_FNS[data.length % GENERATE_FNS.size]
  begin
    fn.call(str)
  rescue SystemStackError
  rescue JSON::ParserError
  rescue JSON::GeneratorError
  rescue EncodingError, ArgumentError, TypeError
  rescue StandardError
  end
  0
end

Ruzzy.fuzz(test_one_input)
