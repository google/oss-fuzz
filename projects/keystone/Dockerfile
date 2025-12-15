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

FROM gcr.io/oss-fuzz-base/base-builder:ubuntu-24-04
RUN apt-get update && apt-get install -y make cmake
RUN git clone --depth 1 https://github.com/keystone-engine/keystone.git
# Prepare tests
RUN export CFLAGS="-pthread" && \
    export CXXFLAGS="-pthread" && \
    cd keystone/bindings/python && \
    make install -j$(nproc) && \
    python3 -m pip install .
WORKDIR $SRC
COPY *.sh $SRC/
