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

RUN apt-get update && apt-get install -y ninja-build cmake \
                       flex libc-ares-dev \
                       libglib2.0-dev libgcrypt20-dev

RUN git clone --depth=1 https://gitlab.com/wireshark/wireshark.git
RUN git clone --depth=1 https://bitbucket.org/jwzawadzki/wireshark-fuzzdb.git

WORKDIR wireshark
COPY build.sh $SRC/
