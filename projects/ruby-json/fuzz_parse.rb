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
require 'bigdecimal'

# Exercises ext/json/ext/parser/parser.c (1701 LOC) including:
# - SIMD-accelerated string scanning (SSE2/NEON paths in simd/simd.h)
# - rvalue_cache binary search + interning (json_string_fastpath)
# - All option-gated code paths
ON_LOAD = ->(obj) { obj }

PARSE_FNS = [
  # Default path — exercises main SIMD scan + rvalue_cache
  ->(str) { JSON.parse(str) },
  # symbolize_names: rb_str_intern() on every key (json_string_fastpath symbolize branch)
  ->(str) { JSON.parse(str, symbolize_names: true) },
  # freeze: rb_obj_freeze() on each parsed string/array/hash
  ->(str) { JSON.parse(str, freeze: true) },
  # allow_nan: NaN / Infinity / -Infinity parsing (separate branches in json_parse_float)
  ->(str) { JSON.parse(str, allow_nan: true) },
  # allow_trailing_comma: exercises trailing comma handling in arrays and objects
  ->(str) { JSON.parse(str, allow_trailing_comma: true) },
  # decimal_class: calls rb_funcallv(BigDecimal, :new, float_string) for every float
  ->(str) { JSON.parse(str, decimal_class: BigDecimal) },
  # allow_duplicate_key: skips duplicate key warning, exercises hash aset path
  ->(str) { JSON.parse(str, allow_duplicate_key: true) },
  # on_load: rb_proc_call_with_block after every top-level object
  ->(str) { JSON.parse(str, on_load: ON_LOAD) },
].freeze

test_one_input = lambda do |data|
  return 0 if data.empty?
  str = data.to_s
  fn = PARSE_FNS[data.length % PARSE_FNS.size]
  begin
    fn.call(str)
  rescue SystemStackError
  rescue JSON::ParserError    # covers ParserError + NestingError (< ParserError)
  rescue EncodingError, ArgumentError, TypeError
  rescue StandardError
  end
  0
end

Ruzzy.fuzz(test_one_input)
