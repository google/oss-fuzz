# frozen_string_literal: true
# Copyright 2024 Google LLC
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
require 'ruzzy'
require 'ox'

class MyHandler < Ox::Sax
  # Called for the opening of an element
  def start_element(name)
  end

  # Called for the text content of an element
  def text(value)
  end

  # Called for the closing of an element
  def end_element(name)
  end
end

test_one_input = lambda do |data|
  begin
    handler = MyHandler.new
    Ox.sax_parse(handler, StringIO.new(data))
  rescue Ox::ParseError, EncodingError
    # pass
  end
  return 0
end

Ruzzy.fuzz(test_one_input)
