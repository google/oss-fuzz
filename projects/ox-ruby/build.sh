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

export GEM_HOME=$OUT/fuzz_parse-gem

# setup
BUILD=$WORK/Build

cd $SRC/ox-ruby
gem build
RUZZY_DEBUG=1 gem install --development --verbose *.gem

# Sync gems folder with ruzzy
rsync -avu /install/ruzzy/* $OUT/fuzz_parse-gem

#for fuzz_target_path in $SRC/harnesses/fuzz_*.rb; do
#	ruzzy-build "$fuzz_target_path"
#done

cp $SRC/harnesses/fuzz_parse.rb $OUT/
export GEM_PATH=$OUT/fuzz_parse-gem

echo """#!/usr/bin/env bash
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=\$(dirname \"\$0\")

echo "GEM_HOME FIRST: \$GEM_HOME"

export GEM_HOME=\$this_dir/fuzz_parse-gem
export GEM_PATH=\$this_dir/fuzz_parse-gem
echo "GEM_PATH: \$GEM_PATH"
echo "GEM_HOME: \$GEM_HOME"
echo "Showing gem home:"
ls -la \$GEM_HOME

echo "Showing this dir:"
ls -la \$this_dir

ASAN_OPTIONS="allocator_may_return_null=1:detect_leaks=0:use_sigaltstack=0" LD_PRELOAD=\$(ruby -e 'require \"ruzzy\"; print Ruzzy::ASAN_PATH') ruby \$this_dir/fuzz_parse.rb \$@""" > $OUT/fuzz_parse

chmod +x $OUT/fuzz_parse

#mv $OUT/fuzz-gem $OUT/fuzz_parse-gem
