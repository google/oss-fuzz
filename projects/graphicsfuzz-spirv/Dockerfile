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
RUN apt-get update && apt-get install -y cmake ninja-build && apt-get install -y maven && apt-get install -y openjdk-8-jdk-headless && apt-get install -y wget

RUN mkdir -p graphicsfuzz-spirv

RUN git clone --depth=1 https://github.com/KhronosGroup/glslang.git graphicsfuzz-spirv/glslang
RUN git clone --depth=1 https://github.com/KhronosGroup/SPIRV-Cross.git graphicsfuzz-spirv/SPIRV-Cross
RUN git clone --depth=1 https://github.com/KhronosGroup/SPIRV-Tools.git graphicsfuzz-spirv/SPIRV-Tools
RUN git clone --depth=1 https://github.com/KhronosGroup/SPIRV-Headers graphicsfuzz-spirv/SPIRV-Tools/external/spirv-headers
RUN git clone --depth=1 https://github.com/google/effcee graphicsfuzz-spirv/SPIRV-Tools/external/effcee
RUN git clone --depth=1 https://github.com/google/re2 graphicsfuzz-spirv/SPIRV-Tools/external/re2

# Cloning with --depth=1 does not work for GraphicsFuzz due to GraphicsFuzz doing a git commit check during its build process.
RUN git clone https://github.com/google/graphicsfuzz.git graphicsfuzz-spirv/graphicsfuzz

COPY build.sh $SRC/

WORKDIR graphicsfuzz-spirv