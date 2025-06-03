# Copyright 2024 Google LLC
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
RUN apt-get update && apt-get install -y make cmake autoconf automake libtool zlib1g-dev flex libssl-dev pkg-config libpcap-dev libpcre3-dev libdumbnet-dev libhwloc-dev libluajit-5.1-dev liblzma-dev
RUN git clone https://github.com/snort3/libdaq.git
#TODO use official repo
RUN git clone --depth 1 --branch fuzz https://github.com/catenacyber/snort3
COPY build.sh $SRC/
WORKDIR $SRC/snort3
