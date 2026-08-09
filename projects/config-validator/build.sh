#!/bin/bash -eu
# Copyright 2021 Google LLC
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

# Copy the library files needed to initialize the validator.
mkdir -p $OUT/validatorfiles
cp -a 'test/cf/constraints' $OUT/validatorfiles
cp -a 'test/cf/library' $OUT/validatorfiles
cp -a 'test/cf/templates' $OUT/validatorfiles

# Copy the corpus.
zip -jr $OUT/fuzz_config_validator_seed_corpus.zip internal/fuzz/corpus

# Compile the fuzzer.
compile_go_fuzzer github.com/GoogleCloudPlatform/config-validator/internal/fuzz Fuzz fuzz_config_validator
