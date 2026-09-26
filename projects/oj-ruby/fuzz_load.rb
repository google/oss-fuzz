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
#
################################################################################
#
# Fuzz the oj JSON parser across its main load modes:
#   - strict   : RFC-compliant JSON only
#   - compat   : json gem compatible behaviour
#   - object   : Ruby-object encoding/decoding
#   - custom   : custom.c — most feature-rich mode with many option branches
#   - rails    : rails.c — ActiveSupport-compatible mode
#   - wab      : wab.c   — WAB protocol mode
#
# Option variants exercise different C-level branches within each mode:
#   allow_nan              — activates NaN/Infinity parsing in the C code
#   allow_invalid_unicode  — changes UTF-8 validation logic
#   bigdecimal_load: :auto — exercises the BigDecimal creation path

require 'ruzzy'
require 'oj'
# Load JSON stdlib so that JSON::ParserError is defined when oj runs in
# compat mode and raises it.
require 'json'

PARSE_MODES = [
  ->(s) { Oj.load(s, mode: :strict) },
  ->(s) { Oj.load(s, mode: :compat) },
  ->(s) { Oj.load(s, mode: :object) },
  ->(s) { Oj.load(s, mode: :custom) },
  ->(s) { Oj.load(s, mode: :rails) },
  ->(s) { Oj.load(s, mode: :wab) },
  ->(s) { Oj.safe_load(s) },
  ->(s) { Oj.strict_load(s) },
  ->(s) { Oj.compat_load(s) },
  ->(s) { Oj.wab_load(s) },
  # Option variants — toggle different C-level conditional branches.
  ->(s) { Oj.load(s, mode: :strict,  allow_nan: true) },
  ->(s) { Oj.load(s, mode: :compat,  allow_invalid_unicode: true) },
  ->(s) { Oj.load(s, mode: :custom,  bigdecimal_load: :auto) },
].freeze

test_one_input = lambda do |data|
  # Allow single-byte inputs — they exercise the initial dispatch logic.
  return 0 if data.empty?

  # Convert raw bytes to a string. oj operates on UTF-8/binary strings.
  str = data.to_s

  # Cycle through parse modes based on input length to exercise all code paths.
  mode_fn = PARSE_MODES[data.length % PARSE_MODES.size]

  begin
    mode_fn.call(str)
  rescue Oj::ParseError, Oj::Error,
         JSON::ParserError, JSON::NestingError,
         EncodingError, ArgumentError, TypeError, RangeError,
         SystemStackError
    # Expected error conditions — not a bug.
  rescue StandardError
    # Catch-all for any other expected Ruby-level errors.
    # ASan/sanitizers still catch memory-safety bugs at the C level.
  end

  0
end

Ruzzy.fuzz(test_one_input)
