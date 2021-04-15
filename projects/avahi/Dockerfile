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
RUN apt-get update && \
    apt-get install -y autoconf gettext libtool m4 automake pkg-config libexpat-dev libexpat-dev:i386
RUN git clone --depth 1 https://github.com/lathiat/avahi
WORKDIR avahi
COPY build.sh avahi_packet_consume_record_fuzzer.cc avahi_packet_consume_key_fuzzer.cc $SRC/
