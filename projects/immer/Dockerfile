# Copyright 2020 Google Inc.
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

FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && apt-get install -y cmake libgc-dev pkg-config
# install Catch2 from sources, since Ubuntu 20.04 (currently the base for
# this image) does not ship it
RUN git clone -b v2.x --depth 1 https://github.com/catchorg/Catch2.git && \
    cd Catch2 && \
    cmake -DCATCH_BUILD_TESTING=OFF -DCATCH_BUILD_EXAMPLES=OFF -DCATCH_ENABLE_COVERAGE=OFF -DCATCH_ENABLE_WERROR=OFF -DCATCH_INSTALL_DOCS=OFF -DCATCH_INSTALL_HELPERS=OFF -Bbuild && \
    cmake --build build && \
    cmake --build build --target install
RUN git clone --depth 1 https://github.com/arximboldi/immer.git immer
WORKDIR immer
COPY build.sh $SRC/
