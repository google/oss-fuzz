#!/bin/bash

# Script for generating fuzztest.bazelrc.

set -euf -o pipefail

echo "### DO NOT EDIT. Generated file.
#
# To regenerate, run the following from your project's workspace:
#
#  bazel run @com_google_fuzztest//bazel:setup_configs > fuzztest.bazelrc
#
# And don't forget to add the following to your project's .bazelrc:
#
#  try-import %workspace%/fuzztest.bazelrc
"

echo "
### Common options.
#
# Do not use directly.

# Link with Address Sanitizer (ASAN).
build:fuzztest-common --linkopt=-fsanitize=address

# Standard define for \"ifdef-ing\" any fuzz test specific code.
build:fuzztest-common --copt=-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION

# In fuzz tests, we want to catch assertion violations even in optimized builds.
build:fuzztest-common --copt=-UNDEBUG
"

echo "
### FuzzTest build configuration.
#
# Use with: --config=fuzztest

build:fuzztest --config=fuzztest-common

# Link statically.
build:fuzztest --dynamic_mode=off

# We rely on the following flag instead of the compiler provided
# __has_feature(address_sanitizer) to know that we have an ASAN build even in
# the uninstrumented runtime.
build:fuzztest --copt=-DADDRESS_SANITIZER
"

REPO_NAME="${1}"
# When used in the fuzztest repo itself.
if [ ${REPO_NAME} == "@" ]; then
  FUZZTEST_FILTER="//fuzztest:"
# When used in client repo.
elif [ ${REPO_NAME} == "@com_google_fuzztest" ]; then
  FUZZTEST_FILTER="fuzztest/.*"
else
  echo "Unexpected repo name: ${REPO_NAME}"
  exit 1
fi

echo "# We apply coverage tracking and ASAN instrumentation to everything but the
# FuzzTest framework itself (including GoogleTest and GoogleMock).
build:fuzztest --per_file_copt=+//,-${FUZZTEST_FILTER},-googletest/.*,-googlemock/.*@-fsanitize=address,-fsanitize-coverage=inline-8bit-counters,-fsanitize-coverage=trace-cmp
"

# Do not use the extra configurations below, unless you know what you're doing.

EXTRA_CONFIGS="${EXTRA_CONFIGS:-none}"

if [[ ${EXTRA_CONFIGS} == *"libfuzzer"* ]]; then

# Find llvm-config.
LLVM_CONFIG=$(command -v llvm-config    ||
              command -v llvm-config-15 ||
              command -v llvm-config-14 ||
              command -v llvm-config-13 ||
              command -v llvm-config-12 ||
              echo "")

if [[ -z "${LLVM_CONFIG}" ]]; then
  echo "ERROR: Couldn't generate config, because cannot find llvm-config."
  echo ""
  echo "Please install clang and llvm, e.g.:"
  echo ""
  echo "  sudo apt install clang llvm"
  exit 1
fi

echo "
### libFuzzer compatibility mode.
#
# Use with: --config=libfuzzer

build:libfuzzer --config=fuzztest-common
build:libfuzzer --copt=-DFUZZTEST_COMPATIBILITY_MODE
build:libfuzzer --copt=-fsanitize=fuzzer-no-link
build:libfuzzer --per_file_copt=+//,-${FUZZTEST_FILTER},-googletest/.*,-googlemock/.*@-fsanitize=address
build:libfuzzer --linkopt=$(find $(${LLVM_CONFIG} --libdir) -name libclang_rt.fuzzer_no_main-x86_64.a | head -1)
"

fi # libFuzzer

echo "
### oss-fuzz compatibility mode.
#
# Use with: --config=oss-fuzz
build:oss-fuzz --config=fuzztest-common
build:oss-fuzz --copt=-DFUZZTEST_COMPATIBILITY_MODE
build:oss-fuzz --dynamic_mode=off
"
if [ "$SANITIZER" = "address" ]; then
  echo "build:oss-fuzz --copt=-fsanitize=fuzzer-no-link"
  echo "build:oss-fuzz --per_file_copt=+//,-${FUZZTEST_FILTER},-googletest/.*,-googlemock/.*@-fsanitize=address"
fi
if [ "$SANITIZER" = "undefined" ]; then
  echo "build:oss-fuzz --copt=-fsanitize=fuzzer-no-link"
  echo "build:oss-fuzz --per_file_copt=+//,-${FUZZTEST_FILTER},-googletest/.*,-googlemock/.*@-fsanitize=undefined"
  echo "build:oss-fuzz --linkopt=$(find $(llvm-config --libdir) -name libclang_rt.ubsan_standalone_cxx-x86_64.a | head -1)"
fi
if [ "$SANITIZER" = "coverage" ]; then
  echo "build:oss-fuzz --per_file_copt=+//,-${FUZZTEST_FILTER},-googletest/.*,-googlemock/.*@-fprofile-instr-generate"
  echo "build:oss-fuzz --per_file_copt=+//,-${FUZZTEST_FILTER},-googletest/.*,-googlemock/.*@-fcoverage-mapping"
  echo "build:oss-fuzz --linkopt=-fprofile-instr-generate"
  echo "build:oss-fuzz --linkopt=-fcoverage-mapping"
fi
echo "
build:oss-fuzz --linkopt=$(find $(${LLVM_CONFIG} --libdir) -name libclang_rt.fuzzer_no_main-x86_64.a | head -1)
"
