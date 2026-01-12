#!/bin/bash -eu
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

# Build the ox gem
cd $SRC/ox-ruby
gem build
gem install --install-dir $OUT/fuzz-gem --verbose *.gem

# Set up gem environment
export GEM_HOME=$OUT/fuzz-gem
export GEM_PATH=$OUT/fuzz-gem:/usr/local/lib/ruby/gems/3.3.0

# Copy Ruzzy and dependencies (for normal fuzzing, not needed for coverage)
if [[ "$SANITIZER" != "coverage" ]]; then
    rsync -avu /install/ruzzy/bin /install/ruzzy/build_info /install/ruzzy/cache /install/ruzzy/doc /install/ruzzy/extensions /install/ruzzy/gems /install/ruzzy/plugins /install/ruzzy/specifications $OUT/fuzz-gem/
fi

# Create fuzzer executables from harness files
for fuzz_target_path in $SRC/harnesses/fuzz_*.rb; do
    if [ ! -f "$fuzz_target_path" ]; then
        continue
    fi
    
    # Use unified builder that handles both fuzzing and coverage modes
    /usr/bin/build_ruby_fuzzer "$fuzz_target_path" "$OUT" "ox-ruby"
done
