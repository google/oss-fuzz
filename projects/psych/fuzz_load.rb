# frozen_string_literal: true
# Copyright 2025 Google LLC
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
require 'psych'

# Trap SIGALRM to prevent "Alarm clock" crashes from libFuzzer's timeout mechanism
# See: https://github.com/trailofbits/ruzzy/issues/22
Signal.trap('ALRM') { }

# Custom handler for testing event-based parsing
class FuzzHandler < Psych::Handler
  def start_stream(encoding); end
  def end_stream; end
  def start_document(version, tag_directives, implicit); end
  def end_document(implicit); end
  def alias(anchor); end
  def scalar(value, anchor, tag, plain, quoted, style); end
  def start_sequence(anchor, tag, implicit, style); end
  def end_sequence; end
  def start_mapping(anchor, tag, implicit, style); end
  def end_mapping; end
end

test_one_input = lambda do |data|
  # Skip very short inputs
  return 0 if data.bytesize < 4

  # Limit input size to prevent timeouts
  return 0 if data.bytesize > 10000

  begin
    # Test Psych.safe_load - safest parsing with restricted class loading
    Psych.safe_load(data)
  rescue Psych::SyntaxError, Psych::DisallowedClass, Psych::AliasesNotEnabled,
         Psych::BadAlias, Psych::AnchorNotDefined,
         ArgumentError, Encoding::UndefinedConversionError,
         Encoding::InvalidByteSequenceError, TypeError, KeyError
    # Expected exceptions for malformed YAML
  end

  begin
    # Test Psych.safe_load with symbolize_names
    Psych.safe_load(data, symbolize_names: true)
  rescue Psych::SyntaxError, Psych::DisallowedClass, Psych::AliasesNotEnabled,
         Psych::BadAlias, Psych::AnchorNotDefined,
         ArgumentError, Encoding::UndefinedConversionError,
         Encoding::InvalidByteSequenceError, TypeError, KeyError
  end

  begin
    # Test Psych.safe_load with freeze option
    Psych.safe_load(data, freeze: true)
  rescue Psych::SyntaxError, Psych::DisallowedClass, Psych::AliasesNotEnabled,
         Psych::BadAlias, Psych::AnchorNotDefined,
         ArgumentError, Encoding::UndefinedConversionError,
         Encoding::InvalidByteSequenceError, TypeError, KeyError
  end

  begin
    # Test Psych.safe_load with aliases enabled
    Psych.safe_load(data, aliases: true)
  rescue Psych::SyntaxError, Psych::DisallowedClass, Psych::AliasesNotEnabled,
         Psych::BadAlias, Psych::AnchorNotDefined,
         ArgumentError, Encoding::UndefinedConversionError,
         Encoding::InvalidByteSequenceError, TypeError, KeyError
  end

  begin
    # Test Psych.load (allows Symbol by default)
    Psych.load(data)
  rescue Psych::SyntaxError, Psych::DisallowedClass, Psych::AliasesNotEnabled,
         Psych::BadAlias, Psych::AnchorNotDefined,
         ArgumentError, Encoding::UndefinedConversionError,
         Encoding::InvalidByteSequenceError, TypeError, KeyError
  end

  begin
    # Test Psych.safe_load_stream for multi-document parsing
    Psych.safe_load_stream(data)
  rescue Psych::SyntaxError, Psych::DisallowedClass, Psych::AliasesNotEnabled,
         Psych::BadAlias, Psych::AnchorNotDefined,
         ArgumentError, Encoding::UndefinedConversionError,
         Encoding::InvalidByteSequenceError, TypeError, KeyError
  end

  begin
    # Test the low-level parser with event handler
    parser = Psych::Parser.new(FuzzHandler.new)
    parser.parse(data)
  rescue Psych::SyntaxError, Psych::BadAlias, Psych::AnchorNotDefined,
         ArgumentError, Encoding::UndefinedConversionError,
         Encoding::InvalidByteSequenceError, TypeError, KeyError
  end

  begin
    # Test parse_stream which builds AST
    ast = Psych.parse_stream(data)
    # If parsing succeeded, try to emit it back
    if ast
      ast.to_yaml
    end
  rescue Psych::SyntaxError, Psych::BadAlias, Psych::AnchorNotDefined,
         ArgumentError, Encoding::UndefinedConversionError,
         Encoding::InvalidByteSequenceError, TypeError, KeyError
  end

  0
end

Ruzzy.fuzz(test_one_input)
