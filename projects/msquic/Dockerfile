# Copyright 2022 Google Inc.
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

ADD https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb packages-microsoft-prod.deb
RUN apt-get update && \
    apt-get install -y software-properties-common && \
    dpkg -i packages-microsoft-prod.deb && \
    add-apt-repository universe && \
    apt-get update -y && \
    apt-get install -y powershell cmake && \
    rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/microsoft/msquic && \
    cd msquic && \
    git submodule init submodules/clog && \
    git submodule init submodules/openssl && \
    git submodule init submodules/googletest && \
    git submodule update
COPY build.sh $SRC/
WORKDIR $SRC/msquic
