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

export GEM_HOME=$OUT/psych-gem

# Prepare libyaml source for building with psych
cd $SRC/libyaml
./bootstrap

# Build psych gem with libyaml source
cd $SRC/psych

gem build psych.gemspec
RUZZY_DEBUG=1 gem install --development --verbose *.gem -- \
  --with-libyaml-source-dir=$SRC/libyaml

# Sync gems folder with ruzzy
rsync -avu /install/ruzzy/* $OUT/psych-gem

# Create seed corpus from yaml-test-suite
mkdir -p $SRC/corpus
find $SRC/yaml-test-suite -name "*.yaml" -o -name "*.yml" | while read f; do
  # Use hash of filepath as unique name
  name=$(echo "$f" | md5sum | cut -c1-16)
  cp "$f" "$SRC/corpus/$name"
done

# Install each fuzzer
for fuzz_target_path in $SRC/harnesses/fuzz_*.rb; do
  fuzz_target_name=$(basename "$fuzz_target_path" .rb)

  cp "$fuzz_target_path" "$OUT/"

  # Create wrapper script
  cat > "$OUT/$fuzz_target_name" << EOF
#!/usr/bin/env bash
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=\$(dirname "\$0")

export GEM_HOME=\$this_dir/psych-gem
export GEM_PATH=\$this_dir/psych-gem

ASAN_OPTIONS="allocator_may_return_null=1:detect_leaks=0:use_sigaltstack=0" LD_PRELOAD=\$(ruby -e 'require "ruzzy"; print Ruzzy::ASAN_PATH') ruby \$this_dir/${fuzz_target_name}.rb \$@
EOF

  chmod +x "$OUT/$fuzz_target_name"

  # Create seed corpus zip from yaml-test-suite files
  zip -j "$OUT/${fuzz_target_name}_seed_corpus.zip" $SRC/corpus/*
done
