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
require 'msgpack'

# Exercises MessagePack.unpack / MessagePack.load (factory_class.c → unpacker.c)
# with option variants that exercise distinct C code paths.
UNPACK_FNS = [
  # Default path: string → full_unpack via DefaultFactory
  ->(str) { MessagePack.unpack(str) },
  # symbolize_keys: rb_str_intern() on every map key (buffer.h: read_top_as_symbol)
  ->(str) { MessagePack.unpack(str, symbolize_keys: true) },
  # freeze: rb_obj_freeze() on each deserialized object
  ->(str) { MessagePack.unpack(str, freeze: true) },
  # allow_unknown_ext: returns ExtensionValue instead of raising UnknownExtTypeError
  ->(str) { MessagePack.unpack(str, allow_unknown_ext: true) },
  # key_cache: exercises rstring_cache_fetch / build_interned_string (buffer.h)
  # — binary-searches a sorted VALUE array and does MEMMOVE, distinct memory paths
  ->(str) { MessagePack.unpack(str, symbolize_keys: true, key_cache: true) },
].freeze

test_one_input = lambda do |data|
  return 0 if data.empty?
  str = data.to_s
  fn = UNPACK_FNS[data.length % UNPACK_FNS.size]
  begin
    fn.call(str)
  rescue NoMemoryError    # rb_str_buf_new(huge_length) returns NULL → Ruby raises this
  rescue SystemStackError # inherits from Exception, not StandardError — not caught below
  rescue EOFError
  rescue MessagePack::UnpackError  # covers Malformed/Stack/UnexpectedType/UnknownExt
  rescue EncodingError, ArgumentError, TypeError, RangeError
  rescue StandardError
  end
  0
end

Ruzzy.fuzz(test_one_input)
