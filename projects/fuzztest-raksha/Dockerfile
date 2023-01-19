# Copyright 2022 Google LLC
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
RUN apt-get update && apt-get install -y make autoconf automake libtool default-jdk bison m4 \
    build-essential\
    curl \
    doxygen \
    flex \
    libffi-dev \
    libncurses5-dev \
    libtool \
    libsqlite3-dev \
    mcpp \
    sqlite \
    uuid-runtime \
    zlib1g-dev 

RUN wget https://github.com/bazelbuild/buildtools/releases/download/4.2.5/buildifier-linux-amd64 \
    -O /usr/local/bin/buildifier && chmod a+x /usr/local/bin/buildifier

RUN git clone https://github.com/google-research/raksha raksha

COPY build.sh $SRC/
COPY *.diff $SRC/
