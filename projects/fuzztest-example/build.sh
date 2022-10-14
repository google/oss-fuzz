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

cd fuzztest
cp -rf ../my_workspace .
cd my_workspace

EXTRA_CONFIGS=libfuzzer \
    bazel run @com_google_fuzztest//bazel:setup_configs > fuzztest.bazelrc

FUZZ_TEST_BINARIES=$(bazel query 'kind("cc_test", rdeps(..., @com_google_fuzztest//fuzztest:fuzztest_gtest_main))')
FUZZ_TEST_BINARIES_OUT_PATHS=$(bazel cquery 'kind("cc_test", rdeps(..., @com_google_fuzztest//fuzztest:fuzztest_gtest_main))' --output=files)

echo "Fuzz test binaries:"
echo ${FUZZ_TEST_BINARIES}
echo "-----------------------------"
#echo ${FUZZ_TEST_BINARIES3}
echo "-----------------------------"

bazel build --subcommands --config=oss-fuzz ${FUZZ_TEST_BINARIES[*]}

echo "Listing tetss:"
for fuzz_main_file in $FUZZ_TEST_BINARIES_OUT_PATHS; do
  FUZZ_TESTS=$($fuzz_main_file --list_fuzz_tests)
  cp ${fuzz_main_file} $OUT/

  fuzz_basename=$(basename $fuzz_main_file)
  for ft in $FUZZ_TESTS; do
    echo "-"
    echo $ft
    TARGET_FUZZER="${fuzz_basename}_GFUZZTEST_$ft"

    # Write executer script
    echo "#!/bin/sh
  # LLVMFuzzerTestOneInput for fuzzer detection.
  this_dir=\$(dirname \"\$0\")
  chmod +x \$this_dir/
  $fuzz_basename --fuzz=$ft -- \$@" > $OUT/$TARGET_FUZZER
    chmod +x $OUT/$TARGET_FUZZER
  done
  echo "------------"
done

# synchronise coverage directory to bazel generated code.
if [ "$SANITIZER" = "coverage" ]
then
  echo "syncing bazel source files to coverage collection"
  declare -r REMAP_PATH="${OUT}/proc/self/cwd"
  mkdir -p "${REMAP_PATH}"

  # Remove symlinks and delete them
  declare -r RSYNC_FILTER_ARGS=("--include" "*.h" "--include" "*.cc" "--include" \
    "*.hpp" "--include" "*.cpp" "--include" "*.c" "--include" "*/" "--exclude" "*")
  rsync -avLk "${RSYNC_FILTER_ARGS[@]}" "${PWD}"/bazel-my_workspace/external "${REMAP_PATH}"

  echo "Deleting symlinks"
  find . -type l -ls -delete
  echo "Done symlinks"
  ls -la 

  rsync -av ${PWD}/ "${REMAP_PATH}"
fi
