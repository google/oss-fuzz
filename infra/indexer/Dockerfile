# Copyright 2026 Google LLC
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

FROM gcr.io/oss-fuzz-base/base-clang-full

RUN mkdir /indexer
WORKDIR /indexer
COPY . /indexer

# Best-effort: the indexer tracks LLVM head while base-clang pins an older LLVM,
# so it regularly fails to compile. Do not let that block the base image builds.
# base-builder checks whether a real binary came out. Keep the '|| true'.
# https://github.com/google/oss-fuzz/issues/16141
RUN apt-get update && apt-get install -y libsqlite3-dev make zlib1g-dev || true
RUN (mkdir build && cd build && cmake .. && cmake --build . -j -v) || true
RUN mkdir -p /indexer/build && touch /indexer/build/indexer
