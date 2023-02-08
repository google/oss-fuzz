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
    --linkopt=${LIB_FUZZING_ENGINE} \
    --linkopt=-Wl,-rpath,'\$ORIGIN/lib' \
    --linkopt=-lgflags \
    --linkopt=-lhogweed \
    --linkopt=-lidn \
    --linkopt=-lnorm \
    --linkopt=-lpgm \
    --linkopt=-lsctp \
    --linkopt=-lsodium \
    --linkopt=-ltspi \
    --linkopt=-lunwind \
    --linkopt=-lzmq \
    ${EXTRA_BAZEL_FLAGS} \
    //lte/gateway/c/core/oai/fuzzing/...:*

cp bazel-bin/lte/gateway/c/core/oai/fuzzing/nas_message_decode $OUT/nas_message_decode
cp bazel-bin/lte/gateway/c/core/oai/fuzzing/nas5g_message_decode $OUT/nas5g_message_decode

zip -j ${OUT}/nas_message_decode_seed_corpus.zip lte/gateway/c/core/oai/fuzzing/nas_message_decode_seed_corpus/*
zip -j ${OUT}/nas5g_message_decode_seed_corpus.zip lte/gateway/c/core/oai/fuzzing/nas5g_message_decode_seed_corpus/*

pushd $OUT
mkdir lib/
cp /lib/libgnutls.* lib/
cp /lib/libhogweed.* lib/
cp /lib/libnettle.* lib/
cp /lib/x86_64-linux-gnu/libconfig.* lib/
cp /lib/x86_64-linux-gnu/libczmq.* lib/
cp /lib/x86_64-linux-gnu/libevent* lib/
cp /lib/x86_64-linux-gnu/libgflags.* lib/
cp /lib/x86_64-linux-gnu/libglog.* lib/
cp /lib/x86_64-linux-gnu/libidn.* lib/
cp /lib/x86_64-linux-gnu/libnorm.* lib/
cp /lib/x86_64-linux-gnu/libpgm* lib/
cp /lib/x86_64-linux-gnu/libsctp.* lib/
cp /lib/x86_64-linux-gnu/libsodium.* lib/
cp /lib/x86_64-linux-gnu/libtspi.* lib/
cp /lib/x86_64-linux-gnu/libunwind.* lib/
cp /lib/x86_64-linux-gnu/libzmq.* lib/
cp /usr/local/lib/libfdcore.* lib/
cp /usr/local/lib/libfdproto.* lib/
popd
