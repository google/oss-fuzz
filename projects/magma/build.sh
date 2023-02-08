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

#Build external dependencies

bazel build \
  @com_github_grpc_grpc//:grpc++ \
  @com_google_protobuf//:protobuf \
  @prometheus_cpp//:prometheus-cpp \
  @yaml-cpp//:yaml-cpp \
  @github_nlohmann_json//:json \
  @sentry_native//:sentry


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
    --linkopt=-lc++ \
    ${EXTRA_BAZEL_FLAGS} \
    //lte/gateway/c/core/oai/fuzzing/...:*

cp bazel-bin/lte/gateway/c/core/oai/fuzzing/nas_message_decode $OUT/nas_message_decode
cp bazel-bin/lte/gateway/c/core/oai/fuzzing/nas5g_message_decode $OUT/nas5g_message_decode


zip -j ${OUT}/nas_message_decode_seed_corpus.zip lte/gateway/c/core/oai/fuzzing/nas_message_decode_seed_corpus/*
zip -j ${OUT}/nas5g_message_decode_seed_corpus.zip lte/gateway/c/core/oai/fuzzing/nas5g_message_decode_seed_corpus/*
