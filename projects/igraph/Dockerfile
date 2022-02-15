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

FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && apt-get install -y make autoconf automake libtool \
  pkg-config cmake bison flex libxml2-dev libxml2-dev:i386 libz-dev libz-dev:i386 liblzma-dev liblzma-dev:i386
RUN git clone --depth 1 --branch develop  https://github.com/igraph/igraph
RUN wget https://github.com/unicode-org/icu/releases/download/release-66-1/icu4c-66_1-src.tgz && tar xzvf icu4c-66_1-src.tgz
WORKDIR igraph
RUN cp $SRC/igraph/fuzzing/build.sh $SRC/build.sh

