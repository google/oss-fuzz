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
RUN apt-get update && apt-get install -y \
    build-essential autoconf automake libssl-dev \
    libpcre3 libpcre3-dev bison libbison-dev \
    libacl1 libacl1-dev libpq-dev lmdb-utils \
    liblmdb-dev libpam0g-dev flex libtool

RUN git clone --depth 1 https://github.com/cfengine/core --recursive
WORKDIR core
COPY build.sh string_fuzzer.c $SRC/
