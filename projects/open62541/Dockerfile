# Copyright 2017 Google Inc.
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
RUN apt-get update && apt-get install -y make cmake python-six wget
# We need libmbedtls > 2.5.1 otherwise it does not include the lib for static linking
RUN wget https://open62541.org/libmbedtls/libmbedtls-dev_2.6.0-1_amd64.deb && \
    wget https://open62541.org/libmbedtls/libmbedcrypto0_2.6.0-1_amd64.deb && \
    wget https://open62541.org/libmbedtls/libmbedtls10_2.6.0-1_amd64.deb && \
    wget https://open62541.org/libmbedtls/libmbedx509-0_2.6.0-1_amd64.deb && \
    dpkg -i *.deb
RUN git clone --depth 1 https://github.com/open62541/open62541.git -bmaster open62541
WORKDIR open62541
RUN git submodule update --init --recursive
COPY build.sh $SRC/
