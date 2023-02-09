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

# Run patch
patch -d /var/tmp/bazel/external/upb/bazel/ < $SRC/build_defs.bzl.patch
patch -d /src/magma/bazel/external/ < $SRC/libfluid_base.BUILD.patch
patch -d /src/magma/bazel/external/ < $SRC/system_libraries.BUILD.patch

ln -s /usr/local/lib/libfdcore.so.6 /lib/x86_64-linux-gnu/libfdcore.so.6
ln -s /usr/local/lib/libfdproto.so.6 /lib/x86_64-linux-gnu/libfdproto.so.6


# Dependency
apt-get install -y libunwind-dev

pushd $SRC/
git clone --depth=1 -b v4.3.2 https://github.com/zeromq/libzmq.git
mkdir libzmq/build/ && cd libzmq/build/
cmake \
    -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
    -DCMAKE_C_FLAGS="" -DCMAKE_CXX_FLAGS="" \
    -DBUILD_SHARED=OFF -DBUILD_TESTS=OFF -DWITH_DOCS=OFF -DZMQ_BUILD_TESTS=OFF ../.
make -j$(nproc)
make install
popd


# Compile
apt-get install -y libtspi-dev libidn11-dev

readonly EXTRA_BAZEL_FLAGS="$(
for f in ${CFLAGS}; do
    echo "--conlyopt=${f}" "--linkopt=${f}"
    echo "--cxxopt=${f}" "--linkopt=${f}"
done
)"

bazel build \
    --dynamic_mode=off \
    --repo_env=CC=${CC} \
    --repo_env=CXX=${CXX} \
    --linkopt=-lsctp \
    --linkopt=-lidn \
    --linkopt=-ltspi \
    --linkopt=-lhogweed \
    --linkopt=${LIB_FUZZING_ENGINE} \
    --linkopt=-Wl,-rpath,'\$ORIGIN/lib' \
    ${EXTRA_BAZEL_FLAGS} \
    //lte/gateway/c/core/oai/fuzzing/...:*

cp bazel-bin/lte/gateway/c/core/oai/fuzzing/nas_message_decode $OUT/nas_message_decode
cp bazel-bin/lte/gateway/c/core/oai/fuzzing/nas5g_message_decode $OUT/nas5g_message_decode

zip -j ${OUT}/nas_message_decode_seed_corpus.zip lte/gateway/c/core/oai/fuzzing/nas_message_decode_seed_corpus/*
zip -j ${OUT}/nas5g_message_decode_seed_corpus.zip lte/gateway/c/core/oai/fuzzing/nas5g_message_decode_seed_corpus/*

mkdir $OUT/lib/
cp /lib/libgnutls* $OUT/lib/.
cp /lib/libnettle* $OUT/lib/.
cp /usr/local/lib/libfdcore* $OUT/lib/.
cp /usr/local/lib/libfdproto* $OUT/lib/.

cp /lib/x86_64-linux-gnu/libsctp* $OUT/lib/.
cp /lib/x86_64-linux-gnu/libidn* $OUT/lib/.
cp /lib/x86_64-linux-gnu/libtspi* $OUT/lib/.
cp /lib/libhogweed* $OUT/lib/.
