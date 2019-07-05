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

# First, determine the latest Bazel we can support
BAZEL_VERSION=$(
  grep '_TF_MAX_BAZEL_VERSION =' configure.py | \
  cut -d\' -f2 | tr -d '[:space:]'
)
if [ -z ${BAZEL_VERSION} ]; then
  echo "Couldn't find a valid bazel version in configure.py script"
  exit 1
fi

# Then, install it
curl -fSsL -O https://github.com/bazelbuild/bazel/releases/download/${BAZEL_VERSION}/bazel-${BAZEL_VERSION}-installer-linux-x86_64.sh
chmod +x ./bazel-${BAZEL_VERSION}-installer-linux-x86_64.sh
./bazel-${BAZEL_VERSION}-installer-linux-x86_64.sh

# Finally, check instalation before proceeding to compile
INSTALLED_VERSION=$(
  bazel version | grep 'Build label' | cut -d: -f2 | tr -d '[:space:]'
)
if [ ${INSTALLED_VERSION} != ${BAZEL_VERSION} ]; then
  echo "Couldn't install required Bazel. "
  echo "Want ${BAZEL_VERSION}. Got ${INSTALLED_VERSION}."
  exit 1
fi

# Generate the list of fuzzers we have (only the base/op name).
FUZZING_BUILD_FILE="tensorflow/core/kernels/fuzzing/BUILD"
declare -r FUZZERS=$(
  grep '^tf_ops_fuzz_target' ${FUZZING_BUILD_FILE} | cut -d'"' -f2 | head -n5
)

# Add a few more flags to make sure fuzzers build and run successfully.
# Note the c++11/libc++ flags to build using the same toolchain as the one used
# to build libFuzzingEngine.
CFLAGS="${CFLAGS} -fno-sanitize=vptr"
CXXFLAGS="${CXXFLAGS} -fno-sanitize=vptr -std=c++11 -stdlib=libc++"

# Make sure we run ./configure to detect when we are using a Bazel out of range
yes "" | ./configure

# See https://github.com/bazelbuild/bazel/issues/6697
sed '/::kM..SeedBytes/d' -i tensorflow/stream_executor/rng.cc

# Due to statically linking boringssl dependency, we have to define one extra
# flag when compiling for memory fuzzing (see the boringssl project).
if [ "$SANITIZER" = "memory" ]
then
  CFLAGS="${CFLAGS} -DOPENSSL_NO_ASM=1"
  CXXFLAGS="${CXXFLAGS} -DOPENSSL_NO_ASM=1"
fi

# All of the flags in $CFLAGS and $CXXFLAGS need to be passed to bazel too.
# Also, pass in flags to ensure static build and to help in debugging failures.
declare -r EXTRA_FLAGS="\
--config=monolithic --dynamic_mode=off \
--verbose_failures \
$(
for f in ${CFLAGS}; do
  echo "--conlyopt=${f}" "--linkopt=${f}"
done
for f in ${CXXFLAGS}; do
  echo "--cxxopt=${f}" "--linkopt=${f}"
done
)"

# We need a new bazel function to build the actual binary.
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
    )
END

# Import this function in the proper BUILD file.
cat >> ${FUZZING_BUILD_FILE} << END

load("//tensorflow/core/kernels/fuzzing:tf_ops_fuzz_target_lib.bzl", "cc_tf")

END

# And invoke it for all fuzzers.
for fuzzer in ${FUZZERS}; do
  echo cc_tf\(\"${fuzzer}\"\) >> ${FUZZING_BUILD_FILE}
done

# Since we force the environment, we expect bazel to fail during the linking of
# each fuzzer. Hence, we will do the linking manually at the end of the process.
# We just need to make sure we use the same invocation as bazel would use, so
# use --verbose_failures (in ${EXTRA_FLAGS}) to get it and then encode it in the
# following ${LINK_ARGS}.
declare -r LINK_ARGS="\
-pthread -fuse-ld=gold \
-Wl,-no-as-needed -Wl,-z,relro,-z,now \
-B/usr/local/bin -B/usr/bin -Wl,--gc-sections \
"

# This should always look as successful despite linking error mentioned above.
bazel build --jobs=2 ${EXTRA_FLAGS} -k //tensorflow/core/kernels/fuzzing:all || true

# For each fuzzer target, we only have to link it manually to get the binary.
for fuzzer in ${FUZZERS}; do
  fz=${fuzzer}_fuzz

  # Get the file with the parameters for linking or fail if it didn't exist.
  lfile=`ls -1 bazel-bin/tensorflow/core/kernels/fuzzing/${fz}*.params | head -n1`

  # Manually link everything.
  ${CXX} ${CXXFLAGS} $LIB_FUZZING_ENGINE -o ${OUT}/${fz} ${LINK_ARGS} -Wl,@${lfile}
done

# For coverage, we need one extra step, see the envoy and grpc projects.
if [ "$SANITIZER" = "coverage" ]
then
  declare -r REMAP_PATH=${OUT}/proc/self/cwd
  mkdir -p ${REMAP_PATH}
  rsync -ak ${SRC}/tensorflow/tensorflow ${REMAP_PATH}
  rsync -ak ${SRC}/tensorflow/third_party ${REMAP_PATH}

  # Also copy bazel generated files (via genrules)
  declare -r BAZEL_PREFIX=bazel-out/k8-opt
  declare -r REMAP_BAZEL_PATH=${REMAP_PATH}/${BAZEL_PREFIX}
  mkdir -p ${REMAP_BAZEL_PATH}
  rsync -ak ${SRC}/tensorflow/${BAZEL_PREFIX}/genfiles ${REMAP_BAZEL_PATH}

  # Finally copy the external archives source files
  rsync -ak ${SRC}/tensorflow/bazel-tensorflow/external ${REMAP_PATH}
fi

# Now that all is done, we just have to copy the existing corpora and
# dictionaries to have them available in the runtime environment.
# The tweaks to the filenames below are to make sure corpora/dictionary have
# similar names as the fuzzer binary.
for dict in tensorflow/core/kernels/fuzzing/dictionaries/*; do
  name=$(basename -- $dict)
  cp ${dict} ${OUT}/${name/.dict/_fuzz.dict}
done
for corpus in tensorflow/core/kernels/fuzzing/corpus/*; do
  name=$(basename -- $corpus)
  zip ${OUT}/${name}_fuzz_seed_corpus.zip ${corpus}/*
done

# Finally, make sure we don't accidentally run with stuff from the bazel cache.
rm -f bazel-*
