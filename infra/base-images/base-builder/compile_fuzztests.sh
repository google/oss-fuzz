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

set -x

# In order to identify fuzztest test case "bazel query" is used to search
# the project. A search of the entire project is done with a default "...",
# however, some projects may fail to, or have very long processing time, if
# searching the entire project. Additionally, it may include fuzzers in
# dependencies, which should not be build as part of a given project.
# Tensorflow is an example project that will fail when the entire project is
# queried. FUZZTEST_TARGET_FOLDER makes it posible to specify the folder
# where fuzztest fuzzers should be search for. FUZZTEST_TARGET_FOLDER is passed
# to "bazel query" below.
if [[ ${FUZZTEST_TARGET_FOLDER:-"unset"} == "unset" ]];
then
  export TARGET_FOLDER="..."
else
  TARGET_FOLDER=${FUZZTEST_TARGET_FOLDER}
fi

BUILD_ARGS="--config=oss-fuzz --subcommands"
if [[ ${FUZZTEST_EXTRA_ARGS:-"unset"} != "unset" ]];
then
  BUILD_ARGS="$BUILD_ARGS ${FUZZTEST_EXTRA_ARGS}"
fi

# Trigger setup_configs rule of fuzztest as it generates the necessary
# configuration file based on OSS-Fuzz environment variables.
bazel run @com_google_fuzztest//bazel:setup_configs >> /etc/bazel.bazelrc

# Bazel target names of the fuzz binaries.
FUZZ_TEST_BINARIES=$(bazel query "kind(\"cc_test\", rdeps(${TARGET_FOLDER}, @com_google_fuzztest//fuzztest:fuzztest_gtest_main))")

# Bazel output paths of the fuzz binaries.
FUZZ_TEST_BINARIES_OUT_PATHS=$(bazel cquery "kind(\"cc_test\", rdeps(${TARGET_FOLDER}, @com_google_fuzztest//fuzztest:fuzztest_gtest_main))" --output=files)

# Build the project and fuzz binaries
# Expose `FUZZTEST_EXTRA_TARGETS` environment variable, in the event a project
# includes non-FuzzTest fuzzers then this can be used to compile these in the
# same `bazel build` command as when building the FuzzTest fuzzers.
# This is to avoid having to call `bazel build` twice.
bazel build $BUILD_ARGS -- ${FUZZ_TEST_BINARIES[*]} ${FUZZTEST_EXTRA_TARGETS:-}

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
\$this_dir/$fuzz_basename --fuzz=$fuzz_entrypoint -- \$@" > $OUT/$TARGET_FUZZER
    chmod +x $OUT/$TARGET_FUZZER
  done
done

# Synchronise coverage directory to bazel output artifacts. This is a
# best-effort basis in that it will include source code in common
# bazel output folders.
# For projects that store results in non-standard folders or want to
# manage what code to include in the coverage report more specifically,
# the FUZZTEST_DO_SYNC environment variable is made available. Projects
# can then implement a custom way of synchronising source code with the
# coverage build. Set FUZZTEST_DO_SYNC to something other than "yes" and
# no effort will be made to automatically synchronise the source code with
# the code coverage visualisation utility.
if [[ "$SANITIZER" = "coverage" && ${FUZZTEST_DO_SYNC:-"yes"} == "yes" ]]
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
                    -e 'bazel-testlogs')"
  for link in $project_folders; do
   if [[ -d "${PWD}"/$link/external  ]]
   then
     rsync -avLk "${RSYNC_FILTER_ARGS[@]}" "${PWD}"/$link/external "${REMAP_PATH}"
   fi
   # k8-opt is a common path for storing bazel output artifacts, e.g. bazel-out/k8-opt.
   # It's the output folder for default amd-64 builds, but projects may specify custom
   # platform output directories, see: https://github.com/bazelbuild/bazel/issues/13818
   # We support the default at the moment, and if a project needs custom synchronizing of
   # output artifacts and code coverage we currently recommend using FUZZTEST_DO_SYNC.
   if [[ -d "${PWD}"/$link/k8-opt  ]]
   then
     rsync -avLk "${RSYNC_FILTER_ARGS[@]}" "${PWD}"/$link/k8-opt "${REMAP_PATH}"/$link
   fi
  done

  # Delete symlinks and sync the current folder.
  find . -type l -ls -delete
  rsync -av ${PWD}/ "${REMAP_PATH}"
fi
