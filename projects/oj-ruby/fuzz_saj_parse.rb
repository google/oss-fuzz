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
# Fuzz the oj SAJ (Simple API for JSON) event-based parser.
# SAJ follows a pull-parser design similar to SAX for XML and exercises a
# separate C code path (saj.c / saj2.c) from the tree-building parser.
#
# The harness alternates between passing a raw String and a StringIO so that
# both the direct parse path (parse.c) and the streaming path (sparse.c)
# are exercised within the SAJ dispatcher.
#
# A minimal handler is used so that SAJ callback overhead is negligible and
# the fuzzer budget is spent on the parser itself.

require 'ruzzy'
require 'oj'
require 'json'
require 'stringio'

# Minimal SAJ handler — all callbacks are no-ops so we exercise the parser
# without spending time building Ruby objects.
class FuzzSajHandler < Oj::Saj
  def hash_start(key); end
  def hash_end(key); end
  def array_start(key); end
  def array_end(key); end
  def add_value(value, key); end
  def error(message, line, column); end
end

HANDLER = FuzzSajHandler.new

test_one_input = lambda do |data|
  return 0 if data.empty?

  str = data.to_s

  begin
    # Alternate between raw String and StringIO to cover both dispatch paths:
    #   String   -> oj_pi_parse  (parse.c / parse_str branch)
    #   StringIO -> oj_pi_sparse (sparse.c / streaming branch)
    #
    # bigdecimal_load: :float prevents BigDecimal object creation, which
    # triggers Ruby GC internals that conflict with ASan stack-frame tracking.
    if data.length.even?
      Oj.saj_parse(HANDLER, str,               bigdecimal_load: :float)
    else
      Oj.saj_parse(HANDLER, StringIO.new(str), bigdecimal_load: :float)
    end
  rescue Oj::ParseError, Oj::Error, JSON::ParserError,
         EncodingError, ArgumentError, TypeError
    # Expected error conditions — not a bug.
  rescue StandardError
    # Catch-all for any other Ruby-level error.
  end

  0
end

Ruzzy.fuzz(test_one_input)
