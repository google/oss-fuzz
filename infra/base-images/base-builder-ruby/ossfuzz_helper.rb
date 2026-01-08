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

# Only require ruzzy in normal fuzzing mode (not in coverage mode)
if ENV["COVERAGE_MODE"] != "true"
  begin
    require 'ruzzy'
  rescue LoadError
    # Ruzzy not available, will fail later if needed
  end
end

module OSSFuzz
  # Unified fuzzing entry point that handles both normal fuzzing and coverage modes.
  #
  # In normal fuzzing mode: calls Ruzzy.fuzz() to start the fuzzing engine
  # In coverage mode: reads corpus file from ARGV[0] and calls the target directly
  #
  # Usage:
  #   fuzz_target = lambda do |data|
  #     # your fuzzing logic
  #   end
  #   OSSFuzz.fuzz(fuzz_target)
  #
  def self.fuzz(fuzz_target)
    if ENV["COVERAGE_MODE"] == "true"
      # Coverage mode: execute target on input file
      data = File.binread(ARGV[0])
      fuzz_target.call(data)
    else
      # Normal fuzzing mode
      Ruzzy.fuzz(fuzz_target)
    end
  end
end
