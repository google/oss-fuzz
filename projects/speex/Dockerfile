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
RUN apt-get update && apt-get install -y make autoconf libtool pkg-config wget
RUN git clone --depth 1 https://gitlab.xiph.org/xiph/ogg.git
RUN git clone --depth 1 https://gitlab.xiph.org/xiph/speex.git speex
# Install more recent wget to work around https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=34762
# "OpenSSL: error:1407742E:SSL routines:SSL23_GET_SERVER_HELLO:tlsv1 alert protocol version"
RUN sed -i -e 's/xenial/bionic/g' /etc/apt/sources.list
RUN apt-get update && apt-get install -y --reinstall wget
WORKDIR speex
COPY build.sh $SRC/
