#!/bin/bash -eu
# Copyright 2023 Google LLC
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

synchronize_coverage_directories() {
  # For coverage, we need to remap source files to correspond to the Bazel build
  # paths. We also need to resolve all symlinks that Bazel creates.
  if [ "$SANITIZER" = "coverage" ]
  then
    declare -r RSYNC_CMD="rsync -aLkR"
    declare -r REMAP_PATH=${OUT}/proc/self/cwd/
    mkdir -p ${REMAP_PATH}

    # Synchronize the folder bazel-BAZEL_OUT_PROJECT.
    declare -r RSYNC_FILTER_ARGS=("--include" "*.h" "--include" "*.cc" "--include" \
      "*.hpp" "--include" "*.cpp" "--include" "*.c" "--include" "*/" "--include" "*.inc" \
      "--exclude" "*")

    # Sync existing code.
    ${RSYNC_CMD} "${RSYNC_FILTER_ARGS[@]}" tensorflow_serving/ ${REMAP_PATH}

    # Sync generated proto files.
    if [ -d "./bazel-out/k8-opt/bin/tensorflow/" ]
    then
      ${RSYNC_CMD} "${RSYNC_FILTER_ARGS[@]}" ./bazel-out/k8-opt/bin/tensorflow_serving/ ${REMAP_PATH}
    fi
    if [ -d "./bazel-out/k8-opt/bin/external" ]
    then
      ${RSYNC_CMD} "${RSYNC_FILTER_ARGS[@]}" ./bazel-out/k8-opt/bin/external/ ${REMAP_PATH}
    fi
    if [ -d "./bazel-out/k8-opt/bin/third_party" ]
    then
      ${RSYNC_CMD} "${RSYNC_FILTER_ARGS[@]}" ./bazel-out/k8-opt/bin/third_party/ ${REMAP_PATH}
    fi

    # Sync external dependencies. We don't need to include `bazel-tensorflow`.
    # Also, remove `external/org_tensorflow` which is a copy of the entire source
    # code that Bazel creates. Not removing this would cause `rsync` to expand a
    # symlink that ends up pointing to itself!
    pushd bazel-serving
    [[ -e external/org_tensorflow ]] && unlink external/org_tensorflow
    ${RSYNC_CMD} external/ ${REMAP_PATH}
    popd
  fi
}

git apply  --ignore-space-change --ignore-whitespace $SRC/tensorflow-serving.diff

bazel run @com_google_fuzztest//bazel:setup_configs >> /etc/bazel.bazelrc
bazel build --config=oss-fuzz --subcommands --spawn_strategy=sandboxed //tensorflow_serving/util:json_tensor_test_fuzz

cp bazel-bin/tensorflow_serving/util/json_tensor_test_fuzz $OUT/json_tensor_test_fuzz

TARGET_FUZZER="json_tensor_test_fuzz@JsonFuzzTest.TheF"
echo "#!/bin/sh
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=\$(dirname \"\$0\")
chmod +x \$this_dir/json_tensor_test_fuzz
\$this_dir/json_tensor_test_fuzz --fuzz=JsonFuzzTest.TheF -- \$@" > $OUT/${TARGET_FUZZER}
chmod +x $OUT/${TARGET_FUZZER}

# Synchronize coverage folders
synchronize_coverage_directories
