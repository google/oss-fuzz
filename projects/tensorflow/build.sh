#!/bin/bash -eu
# Copyright 2018 Google Inc.
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

git apply  --ignore-space-change --ignore-whitespace $SRC/fuzz_patch.patch

# Rename all fuzzer rules to oss-fuzz rules.
find $SRC/tensorflow/tensorflow/ -name "BUILD" -exec sed -i 's/tf_cc_fuzz_test/tf_oss_fuzz_fuzztest/g' {} \;

# Overwrite compiler flags that break the oss-fuzz build
sed -i 's/build:linux --copt=\"-Wno-unknown-warning\"/# overwritten/g' ./.bazelrc
sed -i 's/build:linux --copt=\"-Wno-array-parameter\"/# overwritten/g' ./.bazelrc
sed -i 's/build:linux --copt=\"-Wno-stringop-overflow\"/# overwritten/g' ./.bazelrc

# Force Python3, run configure.py to pick the right build config
PYTHON=python3
yes "" | ${PYTHON} configure.py

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
    ${RSYNC_CMD} "${RSYNC_FILTER_ARGS[@]}" tensorflow/ ${REMAP_PATH}

    # Sync generated proto files.
    if [ -d "./bazel-out/k8-opt/bin/tensorflow/" ]
    then
      ${RSYNC_CMD} "${RSYNC_FILTER_ARGS[@]}" ./bazel-out/k8-opt/bin/tensorflow/ ${REMAP_PATH}
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
    pushd bazel-tensorflow
    [[ -e external/org_tensorflow ]] && unlink external/org_tensorflow
    ${RSYNC_CMD} external/ ${REMAP_PATH}
    popd
  fi
}

# Since Bazel passes flags to compilers via `--copt`, `--conlyopt` and
# `--cxxopt`, we need to move all flags from `$CFLAGS` and `$CXXFLAGS` to these.
# We don't use `--copt` as warnings issued by C compilers when encountering a
# C++-only option results in errors during build.
#
# Note: Make sure that by this line `$CFLAGS` and `$CXXFLAGS` are properly set
# up as further changes to them won't be visible to Bazel.
#
# Note: for builds using the undefined behavior sanitizer we need to link
# `clang_rt` ubsan library. Since Bazel uses `clang` for linking instead of
# `clang++`, we need to add the additional `--linkopt` flag.
# See issue: https://github.com/bazelbuild/bazel/issues/8777
declare -r EXTRA_FLAGS="\
$(
for f in ${CFLAGS}; do
  echo "--conlyopt=${f}" "--linkopt=${f}"
done
for f in ${CXXFLAGS}; do
    echo "--cxxopt=${f}" "--linkopt=${f}"
done
if [ "$SANITIZER" = "undefined" ]
then
  echo "--linkopt=$(find $(llvm-config --libdir) -name libclang_rt.ubsan_standalone_cxx-x86_64.a | head -1)"
  sed -i -e 's/"\/\/conditions:default": \[/"\/\/conditions:default": \[\n"-fno-sanitize=undefined",/' third_party/nasm/nasm.BUILD
  sed -i -e 's/includes/linkopts = \["-fno-sanitize=undefined"\],\nincludes/' third_party/nasm/nasm.BUILD
fi
if [ "$SANITIZER" = "address" ]
then
  echo "--action_env=ASAN_OPTIONS=detect_leaks=0,detect_odr_violation=0"
fi
)"

# Ugly hack to get LIB_FUZZING_ENGINE only for fuzz targets
# and not for other binaries such as protoc
sed -i -e 's/linkstatic/linkopts = \["-fsanitize=fuzzer"\],\nlinkstatic/' tensorflow/security/fuzzing/tf_fuzzing.bzl

# Prepare flags for compiling fuzzers.
export FUZZTEST_EXTRA_ARGS="--spawn_strategy=sandboxed --action_env=ASAN_OPTIONS=detect_leaks=0,detect_odr_violation=0 --define force_libcpp=enabled --verbose_failures --copt=-UNDEBUG --config=monolithic"
if [ -n "${OSS_FUZZ_CI-}" ]
then
  export FUZZTEST_EXTRA_ARGS="${FUZZTEST_EXTRA_ARGS} --local_ram_resources=HOST_RAM*1.0 --local_cpu_resources=HOST_CPUS*.6 --strip=always"
else
  export FUZZTEST_EXTRA_ARGS="${FUZZTEST_EXTRA_ARGS} --local_ram_resources=HOST_RAM*1.0 --local_cpu_resources=HOST_CPUS*.2 --strip=never"
fi

# Do not use compile_fuzztests.sh to synchronize coverage folders as we use
# synchronize_coverage_directories from this script instead.
export FUZZTEST_DO_SYNC="no"

# Set fuzz targets
export FUZZTEST_TARGET_FOLDER="//tensorflow/security/fuzzing/...+//tensorflow/cc/saved_model/...+//tensorflow/cc/framework/fuzzing/...+//tensorflow/core/common_runtime/...+//tensorflow/core/framework/..."
export FUZZTEST_EXTRA_TARGETS="//tensorflow/core/kernels/fuzzing:all"

# Overwrite fuzz targets in CI.
if [ -n "${OSS_FUZZ_CI-}" ]
then
  echo "In CI overwriting targets to only build a single target."
  export FUZZTEST_TARGET_FOLDER="//tensorflow/security/fuzzing/cc:base64_fuzz"
  unset FUZZTEST_EXTRA_TARGETS
fi

echo "  write_to_bazelrc('import %workspace%/tools/bazel.rc')" >> configure.py
yes "" | ./configure

declare FUZZERS=$(grep '^tf_ops_fuzz_target' tensorflow/core/kernels/fuzzing/BUILD | cut -d'"' -f2 | grep -v decode_base64)

cat >> tensorflow/core/kernels/fuzzing/tf_ops_fuzz_target_lib.bzl << END

def cc_tf(name):
    native.cc_test(
        name = name + "_fuzz",
        deps = [
            "//tensorflow/core/kernels/fuzzing:fuzz_session",
            "//tensorflow/core/kernels/fuzzing:" + name + "_fuzz_lib",
            "//tensorflow/cc:cc_ops",
            "//tensorflow/cc:scope",
            "//tensorflow/core:core_cpu",
        ],

	linkopts = ["-fsanitize=fuzzer"]
    )
END

cat >> tensorflow/core/kernels/fuzzing/BUILD << END

load("//tensorflow/core/kernels/fuzzing:tf_ops_fuzz_target_lib.bzl", "cc_tf")

END

for fuzzer in ${FUZZERS}; do
    echo cc_tf\(\"${fuzzer}\"\) >> tensorflow/core/kernels/fuzzing/BUILD
done

declare FUZZERS=$(bazel query 'kind(cc_.*, tests(//tensorflow/core/kernels/fuzzing/...))' | grep -v decode_base64)

# All preparations are done, proceed to build fuzzers.
compile_fuzztests.sh

if [ -n "${OSS_FUZZ_CI-}" ]
then
  # Exit for now in the CI.
  exit 0
fi

# Copy out all non-fuzztest fuzzers.
# The fuzzers built above are in the `bazel-bin/` symlink. But they need to be
# in `$OUT`, so move them accordingly.
for bazel_target in ${FUZZERS}; do
  colon_index=$(expr index "${bazel_target}" ":")
  fuzz_name="${bazel_target:$colon_index}"
  bazel_location="bazel-bin/${bazel_target/:/\/}"
  cp ${bazel_location} ${OUT}/$fuzz_name
  corpus_location=tensorflow/core/kernels/fuzzing/corpus/$(basename ${fuzz_name} _fuzz)
  if [[ -d ${corpus_location} ]]
  then
    find ${corpus_location} -type f | xargs zip -j ${OUT}/${fuzz_name}_seed_corpus.zip
  fi
  dict_location=tensorflow/core/kernels/fuzzing/dictionaries/$(basename ${fuzz_name} _fuzz).dict
  if [[ -f ${dict_location} ]]
  then
    cp ${dict_location} $OUT/${fuzz_name}.dict
  fi
done

# Synchronize coverage folders
synchronize_coverage_directories

# Finally, make sure we don't accidentally run with stuff from the bazel cache.
rm -f bazel-*
