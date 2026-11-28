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

# Exercises the streaming Unpacker API (unpacker_class.c → unpacker.c):
#   feed_each, feed+each, feed+read — distinct code paths from MessagePack.unpack.
STREAM_FNS = [
  # feed_each: canonical streaming API, calls Unpacker_each_impl internally
  ->(str) { MessagePack::Unpacker.new.feed_each(str) {} },
  # feed_each with symbolize_keys
  ->(str) { MessagePack::Unpacker.new(symbolize_keys: true).feed_each(str) {} },
  # feed + each: separate feed and iterator (Unpacker_each via Unpacker_each_impl)
  ->(str) {
    u = MessagePack::Unpacker.new
    u.feed(str)
    u.each {}
  },
  # feed + read loop: exercises Unpacker_read directly until EOFError
  ->(str) {
    u = MessagePack::Unpacker.new(allow_unknown_ext: true)
    u.feed(str)
    loop { u.read }
  },
  # key_cache: exercises rstring_cache_fetch / rsymbol_cache_fetch (buffer.h)
  # — sorted VALUE array binary search + MEMMOVE, distinct from uncached paths
  ->(str) {
    u = MessagePack::Unpacker.new(symbolize_keys: true, key_cache: true)
    u.feed_each(str) {}
  },
].freeze

test_one_input = lambda do |data|
  return 0 if data.empty?
  str = data.to_s
  fn = STREAM_FNS[data.length % STREAM_FNS.size]
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
