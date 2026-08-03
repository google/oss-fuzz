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

# 1) Add tf_oss_fuzz_fuzztest macro to tf_fuzzing.bzl
#    (BUILD files get tf_cc_fuzz_test renamed to tf_oss_fuzz_fuzztest below,
#     so this new function must exist in the .bzl file for them to import.)
cat >> $SRC/tensorflow/tensorflow/security/fuzzing/tf_fuzzing.bzl << 'ENDBZL'

def tf_oss_fuzz_fuzztest(
        name,
        fuzzing_dict = [],
        corpus = [],
        deps = [],
        tags = [],
        **kwargs):
    cc_test(
        name = name,
        deps = deps + [
            "@com_google_fuzztest//fuzztest",
            "@com_google_fuzztest//fuzztest:fuzztest_gtest_main",
        ],
        **kwargs
    )
ENDBZL

# 2) Remove checkpoint_reader_fuzz target (known to cause build failures)
python3 -c "
import re, os
path = os.path.join('$SRC', 'tensorflow', 'tensorflow', 'security', 'fuzzing', 'cc', 'BUILD')
with open(path) as f:
    content = f.read()
content = re.sub(r'\ntf_cc_fuzz_test\(\s*name\s*=\s*\"checkpoint_reader_fuzz\".*?\)\n', '\n', content, flags=re.DOTALL)
with open(path, 'w') as f:
    f.write(content)
"

if [ "$SANITIZER" = "undefined" ]; then
  rm $SRC/tensorflow/tensorflow/security/fuzzing/cc/core/function/BUILD
fi

# Rename all fuzzer rules to oss-fuzz rules.
find $SRC/tensorflow/tensorflow/ -name "BUILD" -exec sed -i 's/tf_cc_fuzz_test/tf_oss_fuzz_fuzztest/g' {} \;

# Make einsum_op_util visible to the fuzzing package
sed -i '/name = "einsum_op_util"/a\    visibility = ["//visibility:public"],' tensorflow/core/util/BUILD

# Overwrite compiler flags that break the oss-fuzz build
sed -i 's/build:linux --copt=\"-Wno-unknown-warning\"/# overwritten/g' ./.bazelrc
sed -i 's/build:linux --copt=\"-Wno-array-parameter\"/# overwritten/g' ./.bazelrc
sed -i 's/build:linux --copt=\"-Wno-stringop-overflow\"/# overwritten/g' ./.bazelrc

# Force Python3, run configure.py to pick the right build config
export TF_PYTHON_VERSION=3.11
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
      "--include" "*.def" "--exclude" "*")

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
# TF uses a hermetic C++ toolchain; -stdlib=libc++ is unsupported and
# causes -Werror failures in deps like boringssl. Filter it out.
CXXFLAGS="${CXXFLAGS//-stdlib=libc++/}"

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
  echo "--linkopt=$(find /usr/local/lib -name 'libclang_rt.ubsan_standalone_cxx*.a' -path '*x86_64*' ! -name '*.syms' | head -1)"
  echo "--linkopt=$(find /usr/local/lib -name 'libclang_rt.ubsan_standalone.a' -path '*x86_64*' | head -1)"
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
# TF's hermetic toolchain can't find the fuzzer_no_main runtime that
# fuzztest's setup_configs normally provides. Find and pass it explicitly.
FUZZER_NO_MAIN_LIB=$(find /usr/local/lib -name "libclang_rt.fuzzer_no_main.a" -path "*x86_64*" 2>/dev/null | head -1)

# On Ubuntu 24.04, the system clang-rt libraries reference C23 glibc symbols
# (__isoc23_strtoul, __isoc23_sscanf, etc.) not in TF's hermetic sysroot
# (glibc 2.27). Provide shims that forward to the older non-C23 equivalents.
# Build the shims in the TF source tree so bazel sandbox can access them.
SHIMS_LIB=$SRC/tensorflow/libglibc_c23_shims.a
cat > /tmp/glibc_c23_shims.c << 'SHIMEOF'
unsigned long strtoul(const char *, char **, int);
unsigned long __isoc23_strtoul(const char *n, char **e, int b) { return strtoul(n, e, b); }
long strtol(const char *, char **, int);
long __isoc23_strtol(const char *n, char **e, int b) { return strtol(n, e, b); }
long long strtoll_l(const char *, char **, int, void *);
long long __isoc23_strtoll_l(const char *n, char **e, int b, void *l) { return strtoll_l(n, e, b, l); }
unsigned long long strtoull(const char *, char **, int);
unsigned long long __isoc23_strtoull(const char *n, char **e, int b) { return strtoull(n, e, b); }
unsigned long long strtoull_l(const char *, char **, int, void *);
unsigned long long __isoc23_strtoull_l(const char *n, char **e, int b, void *l) { return strtoull_l(n, e, b, l); }
int vsscanf(const char *, const char *, __builtin_va_list);
int __isoc23_vsscanf(const char *s, const char *fmt, __builtin_va_list ap) { return vsscanf(s, fmt, ap); }
int __isoc23_sscanf(const char *s, const char *fmt, ...) {
    __builtin_va_list ap;
    __builtin_va_start(ap, fmt);
    int r = vsscanf(s, fmt, ap);
    __builtin_va_end(ap);
    return r;
}
SHIMEOF
clang -c -o /tmp/glibc_c23_shims.o /tmp/glibc_c23_shims.c
ar rcs "${SHIMS_LIB}" /tmp/glibc_c23_shims.o

# For the undefined sanitizer, TF's hermetic linker also can't find the UBSAN
# runtime. Find and add it explicitly alongside the shims.
UBSAN_EXTRA_LINKOPT=""
if [ "$SANITIZER" = "undefined" ]; then
  UBSAN_LIB=$(find /usr/local/lib -name "libclang_rt.ubsan_standalone.a" -path "*x86_64*" ! -name "*.syms" 2>/dev/null | head -1)
  UBSAN_CXX_LIB=$(find /usr/local/lib -name "libclang_rt.ubsan_standalone_cxx.a" -path "*x86_64*" ! -name "*.syms" 2>/dev/null | head -1)
  [ -n "${UBSAN_LIB}" ] && UBSAN_EXTRA_LINKOPT="--linkopt=${UBSAN_LIB}"
  [ -n "${UBSAN_CXX_LIB}" ] && UBSAN_EXTRA_LINKOPT="${UBSAN_EXTRA_LINKOPT} --linkopt=${UBSAN_CXX_LIB}"
fi

export FUZZTEST_EXTRA_ARGS="--spawn_strategy=sandboxed --action_env=ASAN_OPTIONS=detect_leaks=0,detect_odr_violation=0 --define force_libcpp=enabled --verbose_failures --copt=-UNDEBUG --config=monolithic --linkopt=${FUZZER_NO_MAIN_LIB} --linkopt=${SHIMS_LIB} ${UBSAN_EXTRA_LINKOPT}"
if [ -n "${OSS_FUZZ_CI-}" ]
then
  export FUZZTEST_EXTRA_ARGS="${FUZZTEST_EXTRA_ARGS} --local_ram_resources=HOST_RAM*1.0 --local_cpu_resources=HOST_CPUS*.65 --strip=always"
else
  export FUZZTEST_EXTRA_ARGS="${FUZZTEST_EXTRA_ARGS} --local_ram_resources=HOST_RAM*1.0 --local_cpu_resources=HOST_CPUS*.15 --strip=never"
fi

# Do not use compile_fuzztests.sh to synchronize coverage folders as we use
# synchronize_coverage_directories from this script instead.
export FUZZTEST_DO_SYNC="no"

# Set fuzz targets. Exclude cc/ops and core/kernels/fuzzing as they depend on
# ops::Placeholder which was removed from TF's C++ ops API.
export FUZZTEST_TARGET_FOLDER="//tensorflow/security/fuzzing/cc:all+//tensorflow/cc/saved_model/...+//tensorflow/cc/framework/fuzzing/...+//tensorflow/core/common_runtime/...+//tensorflow/core/framework/..."

# Remove the cc/ops BUILD file - those fuzzers use removed Placeholder API
rm -f $SRC/tensorflow/tensorflow/security/fuzzing/cc/ops/BUILD

# Overwrite fuzz targets in CI.
if [ -n "${OSS_FUZZ_CI-}" ]
then
  echo "In CI overwriting targets to only build a single target."
  export FUZZTEST_TARGET_FOLDER="//tensorflow/security/fuzzing/cc:base64_fuzz"
  unset FUZZTEST_EXTRA_TARGETS
fi

echo "  write_to_bazelrc('import %workspace%/tools/bazel.rc')" >> configure.py
yes "" | ./configure

# Old kernel fuzzers (core/kernels/fuzzing/) are disabled - they depend on
# ops::Placeholder which was removed from TF's C++ ops API.

# All preparations are done, proceed to build fuzzers.
compile_fuzztests.sh

if [ -n "${OSS_FUZZ_CI-}" ]
then
  # Exit for now in the CI.
  exit 0
fi

# Synchronize coverage folders
synchronize_coverage_directories

# Finally, make sure we don't accidentally run with stuff from the bazel cache.
rm -f bazel-*
