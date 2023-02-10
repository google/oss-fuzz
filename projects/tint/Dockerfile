# Copyright 2021 Google LLC
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
RUN apt-get update && apt-get install -y make autoconf automake libtool ninja-build \
        libgl-dev libgl-dev \
        libx11-dev libx11-dev:i386 \
        libx11-xcb-dev \
        libxcursor-dev \
        libxext-dev \
        libxi-dev \
        libxinerama-dev \
        libxrandr-dev
RUN git clone 'https://chromium.googlesource.com/chromium/tools/depot_tools.git' --depth 1
ENV PATH="${SRC}/depot_tools:${PATH}"
RUN git clone --depth 1 https://dawn.googlesource.com/dawn dawn
WORKDIR dawn
COPY build.sh $SRC/
