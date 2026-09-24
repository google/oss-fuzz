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
require 'date'

# Trap SIGALRM to prevent "Alarm clock" crashes from libFuzzer's timeout mechanism
# See: https://github.com/trailofbits/ruzzy/issues/22
Signal.trap('ALRM') { }

test_one_input = lambda do |data|
  # Skip very short inputs
  return 0 if data.bytesize < 4

  # Limit input size to prevent timeouts
  return 0 if data.bytesize > 10000

  # Parse input to get a Ruby object
  parsed_obj = nil
  begin
    parsed_obj = Psych.safe_load(data, permitted_classes: [Date, Time, DateTime, Symbol], aliases: true)
  rescue Psych::SyntaxError, Psych::DisallowedClass, Psych::AliasesNotEnabled,
         Psych::BadAlias, Psych::AnchorNotDefined,
         ArgumentError, Encoding::UndefinedConversionError,
         Encoding::InvalidByteSequenceError, TypeError, RangeError, KeyError
    return 0
  end

  # Skip nil results
  return 0 if parsed_obj.nil?

  begin
    # Test Psych.dump - covers the YAMLTree visitor and emitter
    yaml_output = Psych.dump(parsed_obj)

    # Try to re-parse the output for round-trip testing
    Psych.safe_load(yaml_output, permitted_classes: [Date, Time, DateTime, Symbol], aliases: true)
  rescue Psych::SyntaxError, Psych::DisallowedClass, Psych::AliasesNotEnabled,
         Psych::BadAlias, Psych::AnchorNotDefined,
         ArgumentError, Encoding::UndefinedConversionError,
         Encoding::InvalidByteSequenceError, TypeError, RangeError, KeyError
  end

  begin
    # Test Psych.safe_dump
    Psych.safe_dump(parsed_obj)
  rescue Psych::SyntaxError, Psych::DisallowedClass, Psych::AliasesNotEnabled,
         Psych::BadAlias, Psych::AnchorNotDefined,
         ArgumentError, Encoding::UndefinedConversionError,
         Encoding::InvalidByteSequenceError, TypeError, RangeError, KeyError
  end

  begin
    # Test Psych.dump with various options
    Psych.dump(parsed_obj, indentation: 4)
  rescue Psych::SyntaxError, Psych::DisallowedClass,
         Psych::BadAlias, Psych::AnchorNotDefined,
         ArgumentError, Encoding::UndefinedConversionError,
         Encoding::InvalidByteSequenceError, TypeError, RangeError, KeyError
  end

  begin
    # Test Psych.dump with line_width option
    Psych.dump(parsed_obj, line_width: 40)
  rescue Psych::SyntaxError, Psych::DisallowedClass,
         Psych::BadAlias, Psych::AnchorNotDefined,
         ArgumentError, Encoding::UndefinedConversionError,
         Encoding::InvalidByteSequenceError, TypeError, RangeError, KeyError
  end

  begin
    # Test Psych.dump with canonical option
    Psych.dump(parsed_obj, canonical: true)
  rescue Psych::SyntaxError, Psych::DisallowedClass,
         Psych::BadAlias, Psych::AnchorNotDefined,
         ArgumentError, Encoding::UndefinedConversionError,
         Encoding::InvalidByteSequenceError, TypeError, RangeError, KeyError
  end

  begin
    # Test Psych.dump with header option
    Psych.dump(parsed_obj, header: true)
  rescue Psych::SyntaxError, Psych::DisallowedClass,
         Psych::BadAlias, Psych::AnchorNotDefined,
         ArgumentError, Encoding::UndefinedConversionError,
         Encoding::InvalidByteSequenceError, TypeError, RangeError, KeyError
  end

  begin
    # Test Psych.to_json - JSON tree builder and emitter
    Psych.to_json(parsed_obj)
  rescue Psych::SyntaxError, Psych::DisallowedClass,
         Psych::BadAlias, Psych::AnchorNotDefined,
         ArgumentError, Encoding::UndefinedConversionError,
         Encoding::InvalidByteSequenceError, TypeError, RangeError, KeyError
  end

  begin
    # Test dump_stream with multiple parsed objects
    if parsed_obj.is_a?(Array) && parsed_obj.length > 1
      Psych.dump_stream(*parsed_obj)
    end
  rescue Psych::SyntaxError, Psych::DisallowedClass,
         Psych::BadAlias, Psych::AnchorNotDefined,
         ArgumentError, Encoding::UndefinedConversionError,
         Encoding::InvalidByteSequenceError, TypeError, RangeError, KeyError
  end

  0
end

Ruzzy.fuzz(test_one_input)
