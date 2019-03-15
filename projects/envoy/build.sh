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

# Disable UBSan vptr since target built with -fno-rtti.
export CFLAGS="$CFLAGS -fno-sanitize=vptr"
export CXXFLAGS="$CXXFLAGS -fno-sanitize=vptr"

declare -r FUZZER_TARGETS_CC=$(find . -name *_fuzz_test.cc)
declare -r FUZZER_TARGETS="$(for t in ${FUZZER_TARGETS_CC}; do echo "${t:2:-3}"; done)"

FUZZER_DICTIONARIES="\
"

# Skip gperftools, ASAN runs don't use tcmalloc.
export DISABLE_GPERFTOOLS_BUILD=1
sed -i 's#envoy_dependencies()#envoy_dependencies(skip_targets=["tcmalloc_and_profiler","tcmalloc_debug"])#' WORKSPACE

# Copy $CFLAGS and $CXXFLAGS into Bazel command-line flags, for both
# compilation and linking.
#
# Some flags, such as `-stdlib=libc++`, generate warnings if used on a C source
# file. Since the build runs with `-Werror` this will cause it to break, so we
# use `--conlyopt` and `--cxxopt` instead of `--copt`.
#
# While we shouldn't need to set --host_linkopt, it turns out that some builds
# with host toolchains, e.g. protobuf, pickup the fact that we're doing ASAN for
# the target when building libraries but don't cleanly handle the host link for
# build tools (protoc). It seems somewhat harmless to be building protoc ASAN.
declare -r EXTRA_BAZEL_FLAGS="$(
for f in ${CFLAGS}; do
  echo "--conlyopt=${f}" "--linkopt=${f}" "--host_linkopt=${f}"
done
for f in ${CXXFLAGS}; do
  echo "--cxxopt=${f}" "--linkopt=${f}" "--host_linkopt=${f}"
done
)"

declare BAZEL_BUILD_TARGETS=""
declare BAZEL_CORPUS_TARGETS=""
declare FILTERED_FUZZER_TARGETS=""
for t in ${FUZZER_TARGETS}
do
  declare BAZEL_PATH="//"$(dirname "$t")":"$(basename "$t")
  declare TAGGED=$(bazel query "attr('tags', 'no_fuzz', ${BAZEL_PATH})")
  if [ -z "${TAGGED}" ]
  then
    FILTERED_FUZZER_TARGETS+="$t "
    BAZEL_BUILD_TARGETS+="${BAZEL_PATH}_driverless "
    BAZEL_CORPUS_TARGETS+="${BAZEL_PATH}_corpus_tar "
  fi
done

# Override sanitizers, useful for non-Envoy code that we're trying to fix and
# that is acting as a build blockers.
declare -r BLACKLIST_PATH=blacklist.txt
cat <<EOF > "${BLACKLIST_PATH}"
# TODO(htuch): remove when we
# havehttps://github.com/protocolbuffers/protobuf/pull/5901.
fun:*FastInt64ToBufferLeft*
EOF

# Build driverless libraries.
# TODO(htuch): Remove the CC/CXX/CFLAGS/CXXFLAGS passing, this is only there for
# cmake_external limitation in understanding --cxxopt etc., it should not be
# necessary once
# https://github.com/bazelbuild/rules_foreign_cc/issues/154#issuecomment-466504751
# is resolved and we cleanup libc++ support in the main repo.
bazel build --verbose_failures --dynamic_mode=off --spawn_strategy=standalone \
  --genrule_strategy=standalone --strip=never \
  --copt=-fno-sanitize=vptr --linkopt=-fno-sanitize=vptr --linkopt=-lc++fs \
  --copt=-fsanitize-blacklist="${BLACKLIST_PATH}" \
  --define tcmalloc=disabled --define signal_trace=disabled \
  --define ENVOY_CONFIG_ASAN=1 --copt -D__SANITIZE_ADDRESS__ \
  --define force_libcpp=enabled \
  --action_env CC \
  --action_env CXX \
  --action_env CFLAGS \
  --action_env CXXFLAGS \
  --build_tag_filters=-no_asan \
  ${EXTRA_BAZEL_FLAGS} \
  ${BAZEL_BUILD_TARGETS[*]} ${BAZEL_CORPUS_TARGETS[*]}

# Profiling with coverage requires that we resolve+copy all Bazel symlinks and
# also remap everything under proc/self/cwd to correspond to Bazel build paths.
if [ "$SANITIZER" = "coverage" ]
then
  # The build invoker looks for sources in $SRC, but it turns out that we need
  # to not be buried under src/, paths are expected at out/proc/self/cwd by
  # the profiler.
  declare -r REMAP_PATH="${OUT}/proc/self/cwd"
  mkdir -p "${REMAP_PATH}"
  # For .cc, we only really care about source/ today.
  rsync -av "${SRC}"/envoy/source "${REMAP_PATH}"
  rsync -av "${SRC}"/envoy/test "${REMAP_PATH}"
  # Clean up symlinks with a missing referrant.
  find "${SRC}"/envoy/bazel-envoy/external -follow -type l -ls -delete || echo "Symlink cleanup soft fail"
  rsync -avLk "${SRC}"/envoy/bazel-envoy/external "${REMAP_PATH}"
  # For .h, and some generated artifacts, we need bazel-out/. Need to heavily
  # filter out the build objects from bazel-out/. Also need to resolve symlinks,
  # since they don't make sense outside the build container.
  declare -r RSYNC_FILTER_ARGS=("--include" "*.h" "--include" "*.cc" "--include" \
    "*.hpp" "--include" "*.cpp" "--include" "*.c" "--include" "*/" "--exclude" "*")
  rsync -avLk "${RSYNC_FILTER_ARGS[@]}" "${SRC}"/envoy/bazel-out "${REMAP_PATH}"
  rsync -avLkR "${RSYNC_FILTER_ARGS[@]}" "${HOME}" "${OUT}"
  rsync -avLkR "${RSYNC_FILTER_ARGS[@]}" /tmp "${OUT}"
fi

# Copy out test driverless binaries from bazel-bin/.
for t in ${FILTERED_FUZZER_TARGETS}
do
  TARGET_BASE="$(expr "$t" : '.*/\(.*\)_fuzz_test')"
  TARGET_DRIVERLESS=bazel-bin/"${t}"_driverless
  echo "Copying fuzzer $t"
  cp "${TARGET_DRIVERLESS}" "${OUT}"/"${TARGET_BASE}"_fuzz_test
done

# Zip up related test corpuses.
# TODO(htuch): just use the .tar directly when
# https://github.com/google/oss-fuzz/issues/1918 is fixed.
CORPUS_UNTAR_PATH="${PWD}"/_tmp_corpus
for t in ${FILTERED_FUZZER_TARGETS}
do
  echo "Extracting and zipping fuzzer $t corpus"
  rm -rf "${CORPUS_UNTAR_PATH}"
  mkdir -p "${CORPUS_UNTAR_PATH}"
  tar -C "${CORPUS_UNTAR_PATH}" -xvf bazel-bin/"${t}"_corpus_tar.tar
  TARGET_BASE="$(expr "$t" : '.*/\(.*\)_fuzz_test')"
  zip "${OUT}/${TARGET_BASE}"_fuzz_test_seed_corpus.zip \
    "${CORPUS_UNTAR_PATH}"/*
done
rm -rf "${CORPUS_UNTAR_PATH}"

# Copy dictionaries and options files to $OUT/
for d in $FUZZER_DICTIONARIES; do
  cp "$d" "${OUT}"/
done

# Cleanup bazel- symlinks to avoid oss-fuzz trying to copy out of the build
# cache.
rm -f bazel-*
