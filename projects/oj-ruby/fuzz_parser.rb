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
# Fuzz the Oj::Parser API — the newer, faster parser introduced in oj 3.13.
#
# Oj::Parser (parser.c / usual.c / validate.c) is a completely separate C code
# path from the legacy Oj.load parser.  Three delegates exercise different
# internal branches:
#   :usual    — builds Ruby objects (usual.c)
#   :validate — syntax-only check, cheapest path
#
# The :saj delegate variant is intentionally omitted here because saj.c is
# already covered by the fuzz_saj_parse harness.

require 'ruzzy'
require 'oj'

USUAL_PARSER    = Oj::Parser.new(:usual)
VALIDATE_PARSER = Oj::Parser.new(:validate)

PARSERS = [USUAL_PARSER, VALIDATE_PARSER].freeze

test_one_input = lambda do |data|
  return 0 if data.empty?

  str = data.to_s
  parser = PARSERS[data.length % PARSERS.size]

  begin
    parser.parse(str)
  rescue Oj::ParseError, Oj::Error, EncodingError, ArgumentError, TypeError
    # Expected error conditions — not a bug.
  rescue StandardError
    # Catch-all for any other Ruby-level error.
    # ASan/sanitizers still catch memory-safety bugs at the C level.
  end

  0
end

Ruzzy.fuzz(test_one_input)
