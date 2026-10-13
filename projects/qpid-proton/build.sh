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

env
# workaround https://github.com/google/oss-fuzz/issues/9857
ln -s /usr/local/bin/llvm-ar /src/aflplusplus/afl-llvm-ar
ln -s /usr/local/bin/llvm-ranlib /src/aflplusplus/afl-llvm-ranlib

mkdir build
pushd build
  # Upstream compiles with -Werror by default. Newer clang than upstream CI
  # uses rejects the build over warnings that are not fuzzing-relevant: an
  # unused static inline in core/dispatcher.c, and const-qualifier mismatches
  # in ssl/openssl.c against OpenSSL 3.x prototypes. Turn warnings back into
  # warnings so toolchain drift does not keep breaking the build.
  cmake .. \
    -DENABLE_WARNING_ERROR=OFF \
    -DCMAKE_BUILD_TYPE=Release \
    -DENABLE_LINKTIME_OPTIMIZATION=OFF \
    -DBUILD_STATIC_LIBS=ON \
    -DENABLE_FUZZ_TESTING=ON \
    -DFUZZ_REGRESSION_TESTS=OFF
  pushd c/tests/fuzz/
    VERBOSE=1 make -j $(nproc)
  popd
  cp c/tests/fuzz/{fuzz-connection-driver,fuzz-message-decode} $OUT/
popd

zip -j $OUT/fuzz-connection-driver_seed_corpus.zip c/tests/fuzz/fuzz-connection-driver/corpus/* c/tests/fuzz/fuzz-connection-driver/crash/*
zip -j $OUT/fuzz-message-decode_seed_corpus.zip c/tests/fuzz/fuzz-message-decode/corpus/* c/tests/fuzz/fuzz-message-decode/crash/*
