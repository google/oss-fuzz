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
#!/bin/bash -eu

# Testcase 1. Valid fuzzer build.
################################################################################
./configure
make -j$(nproc) clean
make -j$(nproc) all

$CXX $CXXFLAGS -std=c++11 -I. \
    $SRC/bad_example_fuzzer.cc -o $OUT/bad_example_valid_build \
    $LIB_FUZZING_ENGINE ./libz.a


# Testcase 2. Silent startup crash.
################################################################################
./configure
make -j$(nproc) clean
make -j$(nproc) all

$CXX $CXXFLAGS -std=c++11 -I. -DINTENTIONAL_STARTUP_CRASH \
    $SRC/bad_example_fuzzer.cc -o $OUT/bad_example_startup_crash \
    $LIB_FUZZING_ENGINE ./libz.a


# The latest two examples won't work for coverage or introspector, bail out.
if [[ $SANITIZER = *coverage* || $SANITIZER = *introspector* ]]; then
  exit 0
fi


# Testcase 3. Partially ignore the flags provided by OSS-Fuzz.
################################################################################
export CFLAGS_ORIG="$CFLAGS"
export CFLAGS="-O1"
export CXXFLAGS_ORIG="$CXXFLAGS"
export CXXFLAGS="-O1 -stdlib=libc++"

# We need to pass static as zlib fails to build shared lib in OSS-Fuzz env.
./configure --static
make -j$(nproc) clean
make -j$(nproc) all

$CXX -fsanitize=$SANITIZER $CXXFLAGS_ORIG -std=c++11 -I. \
    $SRC/bad_example_fuzzer.cc -o $OUT/bad_example_partial_instrumentation \
    $LIB_FUZZING_ENGINE ./libz.a


# Testcase 4. Completely ignore the flags provided by OSS-Fuzz.
################################################################################
# We need to pass static as zlib fails to build shared lib in OSS-Fuzz env.
./configure --static
make -j$(nproc) clean
make -j$(nproc) all

$CXX -fsanitize=$SANITIZER $CXXFLAGS -std=c++11 -I. \
    $SRC/bad_example_fuzzer.cc -o $OUT/bad_example_no_instrumentation \
    $LIB_FUZZING_ENGINE ./libz.a


# Testcase 5. Enable multiple sanitizers.
################################################################################
# Add UBSan to ASan or MSan build. Add ASan to UBSan build.
EXTRA_SANITIZER="undefined"
if [[ $SANITIZER = *undefined* ]]; then
  EXTRA_SANITIZER="address"
fi

export CFLAGS="$CFLAGS_ORIG -fsanitize=$EXTRA_SANITIZER"
export CXXFLAGS="$CXXFLAGS_ORIG -fsanitize=$EXTRA_SANITIZER"

./configure
make -j$(nproc) clean
make -j$(nproc) all

$CXX $CXXFLAGS -std=c++11 -I. \
    $SRC/bad_example_fuzzer.cc -o $OUT/bad_example_mixed_sanitizers \
    $LIB_FUZZING_ENGINE ./libz.a
