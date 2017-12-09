#!/bin/bash -eu

# Testcase 1. Valid fuzzer build.
################################################################################
./configure
make -j$(nproc) clean
make -j$(nproc) all

$CXX $CXXFLAGS -std=c++11 -I. \
    $SRC/bad_example_fuzzer.cc -o $OUT/bad_example_valid_build \
    -lFuzzingEngine ./libz.a


# Testcase 2. Silent startup crash.
################################################################################
./configure
make -j$(nproc) clean
make -j$(nproc) all

$CXX $CXXFLAGS -std=c++11 -I. -DINTENTIONAL_STARTUP_CRASH \
    $SRC/bad_example_fuzzer.cc -o $OUT/bad_example_startup_crash \
    -lFuzzingEngine ./libz.a


# The latest two examples won't for for coverage build, bail out.
if [[ $SANITIZER = *coverage* ]] || [[ $SANITIZER = *profile* ]]; then
  exit 0
fi


# Testcase 3. Ignore the flags provided by OSS-Fuzz.
################################################################################
export CFLAGS="-O1"
export CXXFLAGS="-O1 -stdlib=libc++"

./configure
make -j$(nproc) clean
make -j$(nproc) all

$CXX -fsanitize=$SANITIZER $CXXFLAGS -std=c++11 -I. \
    $SRC/bad_example_fuzzer.cc -o $OUT/bad_example_no_instrumentation \
    -lFuzzingEngine ./libz.a


# Testcase 4. Enable multiple sanitizers.
################################################################################
# Add UBSan to ASan or MSan build. Add ASan to UBSan build.
EXTRA_SANITIZER="undefined"
if [[ $SANITIZER = *undefined* ]]; then
  EXTRA_SANITIZER="address"
fi

export CFLAGS="-O1 -fsanitize=$SANITIZER,$EXTRA_SANITIZER -fsanitize-coverage=trace-pc-guard,trace-cmp"
export CXXFLAGS="-O1 -fsanitize=$SANITIZER,$EXTRA_SANITIZER -fsanitize-coverage=trace-pc-guard,trace-cmp -stdlib=libc++"

./configure
make -j$(nproc) clean
make -j$(nproc) all

$CXX $CXXFLAGS -std=c++11 -I. \
    $SRC/bad_example_fuzzer.cc -o $OUT/bad_example_mixed_sanitizers \
    -lFuzzingEngine ./libz.a
