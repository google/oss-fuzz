# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && apt-get install -y cmake ninja-build python3
# Temporary until the external-engine and seed-generator changes land on master.
RUN git clone --depth 1 --branch tier-2 https://github.com/loumalouomega/meshioplusplus.git $SRC/meshioplusplus && \
    git -C $SRC/meshioplusplus submodule update --init --depth 1 \
        src/cpp/third_party/eigen src/cpp/third_party/json
WORKDIR $SRC/meshioplusplus
COPY build.sh $SRC/build.sh
