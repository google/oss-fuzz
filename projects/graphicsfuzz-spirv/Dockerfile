# Copyright 2019 Google Inc.
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
MAINTAINER your@email.com
RUN apt-get update && apt-get install -y make autoconf automake libtool

# Get various useful tools
RUN apt-get install -y cmake ninja-build
# RUN apt-get install -y libx11-dev
# RUN apt-get install -y libxext-dev

RUN mkdir -p graphicsfuzz-targets
RUN git clone https://github.com/KhronosGroup/glslang.git graphicsfuzz-targets/glslang
RUN git clone https://github.com/KhronosGroup/SPIRV-Cross.git graphicsfuzz-targets/SPIRV-Cross
RUN git clone https://github.com/KhronosGroup/SPIRV-Tools.git graphicsfuzz-targets/SPIRV-Tools
RUN git clone --depth=1 https://github.com/KhronosGroup/SPIRV-Headers graphicsfuzz-targets/SPIRV-Tools/external/spirv-headers
RUN git clone --depth=1 https://github.com/google/effcee              graphicsfuzz-targets/SPIRV-Tools/external/effcee
RUN git clone --depth=1 https://github.com/google/re2                 graphicsfuzz-targets/SPIRV-Tools/external/re2

COPY build.sh $SRC/

WORKDIR graphicsfuzz-targets