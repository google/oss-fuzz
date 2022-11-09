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

# Trigger setup_configs rule of fuzztest as it generates the necessary
# configuration file based on OSS-Fuzz environment variables.
bazel run @com_google_fuzztest//bazel:setup_configs > fuzztest.bazelrc

# Bazel target names of the fuzz binaries.
FUZZ_TEST_BINARIES=$(bazel query 'kind("cc_test", rdeps(..., @com_google_fuzztest//fuzztest:fuzztest_gtest_main))')

# Bazel output paths of the fuzz binaries.
FUZZ_TEST_BINARIES_OUT_PATHS=$(bazel cquery 'kind("cc_test", rdeps(..., @com_google_fuzztest//fuzztest:fuzztest_gtest_main))' --output=files)

#echo "Fuzz test binaries:"
#echo ${FUZZ_TEST_BINARIES}
#echo "-----------------------------"
#echo ${FUZZ_TEST_BINARIES3}
#echo "-----------------------------"

# Build the project and fuzz binaries
bazel build --subcommands --config=oss-fuzz ${FUZZ_TEST_BINARIES[*]}

# Iterate the fuzz binaries and list each fuzz entrypoint in the binary. For
# each entrypoint create a wrapper script that calls into the binaries the
# given entrypoint as argument.
# The scripts will be named:
# {binary_name}@{fuzztest_entrypoint}
for fuzz_main_file in $FUZZ_TEST_BINARIES_OUT_PATHS; do
  FUZZ_TESTS=$($fuzz_main_file --list_fuzz_tests)
  cp ${fuzz_main_file} $OUT/
  fuzz_basename=$(basename $fuzz_main_file)
  chmod -x $OUT/$fuzz_basename
  for fuzz_entrypoint in $FUZZ_TESTS; do
    TARGET_FUZZER="${fuzz_basename}@$fuzz_entrypoint"

    # Write executer script
    echo "#!/bin/sh
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=\$(dirname \"\$0\")
chmod +x \$this_dir/$fuzz_basename
$fuzz_basename --fuzz=$fuzz_entrypoint -- \$@" > $OUT/$TARGET_FUZZER
    chmod +x $OUT/$TARGET_FUZZER
  done
done

# synchronise coverage directory to bazel generated code.
if [ "$SANITIZER" = "coverage" ]
then 
  # Synchronize bazel source files to coverage collection.
  declare -r REMAP_PATH="${OUT}/proc/self/cwd"
  mkdir -p "${REMAP_PATH}"
  
  # Synchronize the folder bazel-BAZEL_OUT_PROJECT.
  declare -r RSYNC_FILTER_ARGS=("--include" "*.h" "--include" "*.cc" "--include" \
    "*.hpp" "--include" "*.cpp" "--include" "*.c" "--include" "*/" "--include" "*.inc" \
    "--exclude" "*")
  project_folders="$(find . -name 'bazel-*' -type l -printf '%P\n' | \
                    grep -v -x -F \
                    -e 'bazel-bin' \
                    -e 'bazel-out' \
                    -e 'bazel-testlogs')"
  for link in $project_folders; do
   if [[ -d "${PWD}"/$link/external  ]]
   then
     rsync -avLk "${RSYNC_FILTER_ARGS[@]}" "${PWD}"/$link/external "${REMAP_PATH}"
   fi
  done

  # Delete symlinks and sync the current folder.
  find . -type l -ls -delete
  rsync -av ${PWD}/ "${REMAP_PATH}"
fi
