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
MAINTAINER pab.systerel@gmail.com
RUN apt-get update && apt-get install -y make cmake git curl

# Sources and dependencies
RUN git clone --depth 1 https://gitlab.com/systerel/S2OPC
RUN git clone --depth 1 https://gitlab.com/systerel/S2OPC-fuzzing-data
RUN curl -L https://tls.mbed.org/download/mbedtls-2.16.0-apache.tgz -o $SRC/mbedtls.tgz
RUN curl -L https://github.com/libcheck/check/releases/download/0.12.0/check-0.12.0.tar.gz -o $SRC/check.tgz

WORKDIR S2OPC
COPY build.sh $SRC/
