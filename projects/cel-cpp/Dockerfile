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

RUN apt-get update && apt-get install python openjdk-11-jdk -y
RUN git clone --depth 1 https://github.com/google/cel-cpp/
COPY build.sh $SRC/
RUN mkdir $SRC/cel-cpp/fuzz/
COPY BUILD fuzz*.cc $SRC/cel-cpp/fuzz/
COPY WORKSPACE .bazelrc $SRC/
RUN cat WORKSPACE >> $SRC/cel-cpp/WORKSPACE
RUN cat .bazelrc >> $SRC/cel-cpp/.bazelrc
RUN echo "4.1.0" > $SRC/cel-cpp/.bazelversion
WORKDIR $SRC/cel-cpp
# This is to fix Fuzz Introspector build by using LLVM old pass manager
# re https://github.com/ossf/fuzz-introspector/issues/305
ENV OLD_LLVMPASS 1
