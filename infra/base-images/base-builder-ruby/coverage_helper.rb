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

# Coverage helper for Ruby fuzzers
# This script sets up SimpleCov for code coverage collection

require 'simplecov'
require 'json'

# Configure SimpleCov
SimpleCov.start do
  # Set coverage directory from environment or use default
  coverage_dir ENV['COVERAGE_DIR'] || File.join(Dir.pwd, 'coverage')
  
  # Use simple formatter for now, we'll customize the output
  formatter SimpleCov::Formatter::SimpleFormatter
  
  # Track all files
  track_files '**/*.rb'
  
  # Add filters to exclude test files and gems
  add_filter '/spec/'
  add_filter '/test/'
  add_filter 'ossfuzz_helper'
  add_filter 'coverage_helper'
  
  # Enable branch coverage for better insights
  enable_coverage :branch
  
  # Merge results from multiple runs
  use_merging true
  merge_timeout 3600
end

# Store coverage command name based on fuzzer
if ENV['FUZZER_NAME']
  SimpleCov.command_name ENV['FUZZER_NAME']
end
