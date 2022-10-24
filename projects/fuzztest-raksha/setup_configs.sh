#!/bin/bash -eu
# Copyright 2022 Google LLC
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

echo "
### oss-fuzz compatibility mode.
#
# Use with: --config=oss-fuzz
build:oss-fuzz --config=fuzztest-common
build:oss-fuzz --copt=-DFUZZTEST_COMPATIBILITY_MODE
build:oss-fuzz --dynamic_mode=off
build:oss-fuzz --action_env=CC=${CC}
build:oss-fuzz --action_env=CXX=${CXX}
"
for flag in $CFLAGS; do
  # whenever we have something along -fno-sanitize-recover=bool,array,...,.. we
  # need to split them out and write each assignment without use of commas. Otherwise
  # the per_file_copt option splits the comma string with spaces, which causes the
  # build command to be erroneous.
  if [[ $flag == *","* && $flag == *"="* ]]; then
    # Find the first occurence of equals
    sp=(${flag//=/ })
    comma_values=($(echo ${sp[1]} | tr ',' " "))
    for vv in "${comma_values[@]}"; do
      echo "build:oss-fuzz --per_file_copt=+//,-${FUZZTEST_FILTER},-googletest/.*,-googlemock/.*@${sp[0]}=${vv}"
    done
  else
    if [[ $flag != *"no-as-needed"* ]]; then
      echo "build:oss-fuzz --per_file_copt=+//,-${FUZZTEST_FILTER},-googletest/.*,-googlemock/.*@$flag"
    fi
  fi
done

if [ "$SANITIZER" = "undefined" ]; then
  echo "build:oss-fuzz --linkopt=$(find $(llvm-config --libdir) -name libclang_rt.ubsan_standalone_cxx-x86_64.a | head -1)"
fi
if [ "$SANITIZER" = "coverage" ]; then
  echo "build:oss-fuzz --linkopt=-fprofile-instr-generate"
  echo "build:oss-fuzz --linkopt=-fcoverage-mapping"
fi
if [ "$FUZZING_ENGINE" = "libfuzzer" ]; then
  echo "build:oss-fuzz --linkopt=$(find $(llvm-config --libdir) -name libclang_rt.fuzzer_no_main-x86_64.a | head -1)"
fi
# AFL version in oss-fuzz does not support LLVMFuzzerRunDriver. It must be updated first.
#if [ "$FUZZING_ENGINE" = "afl" ]; then
#  echo "build:oss-fuzz --linkopt=${LIB_FUZZING_ENGINE}"
#fi
