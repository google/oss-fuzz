#!/bin/bash -eu
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

cd $SRC/carrierwave

# Build the CarrierWave gem
gem build carrierwave.gemspec

# Install with ruzzy instrumentation
export GEM_HOME=$OUT/carrierwave-gem
RUZZY_DEBUG=1 gem install --verbose *.gem

# Install dependencies required by CarrierWave
gem install activesupport activemodel marcel addressable ssrf_filter image_processing mini_magick --install-dir $OUT/carrierwave-gem

# Rebuild psych gem with static libyaml linking
# The static libyaml was built in Dockerfile and installed to /usr/local
gem install psych --install-dir $OUT/carrierwave-gem -- \
    --with-libyaml-dir=/usr/local \
    --with-libyaml-lib=/usr/local/lib \
    --with-libyaml-include=/usr/local/include

# Sync gems folder with ruzzy
rsync -avu /install/ruzzy/* $OUT/carrierwave-gem/

# Create wrapper scripts for each Ruby fuzzer
for fuzzer in fuzz_sanitized_file fuzz_validation fuzz_uri fuzz_uploader; do
    # Copy the fuzzer harness
    cp $SRC/harnesses/${fuzzer}.rb $OUT/

    # Create the shell wrapper script
    cat > $OUT/${fuzzer} << 'FUZZER_EOF'
#!/usr/bin/env bash
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=$(dirname "$0")
fuzzer_name=$(basename "$0")

export GEM_HOME=$this_dir/carrierwave-gem
export GEM_PATH=$this_dir/carrierwave-gem

ASAN_OPTIONS="allocator_may_return_null=1:detect_leaks=0:use_sigaltstack=0" \
LD_PRELOAD=$(ruby -e 'require "ruzzy"; print Ruzzy::ASAN_PATH') \
ruby $this_dir/${fuzzer_name}.rb "$@"
FUZZER_EOF

    chmod +x $OUT/${fuzzer}
done
