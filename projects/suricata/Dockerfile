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

FROM gcr.io/oss-fuzz-base/base-builder-rust
RUN apt-get update && apt-get install -y build-essential autoconf automake libtool make pkg-config  python flex bison zlib1g-dev libpcre3-dev cmake tshark

# TODO libmagic, liblzma and other optional libraries
ADD https://github.com/PhilipHazel/pcre2/releases/download/pcre2-10.39/pcre2-10.39.tar.gz pcre2-10.39.tar.gz
ADD https://www.tcpdump.org/release/libpcap-1.9.1.tar.gz libpcap-1.9.1.tar.gz
ADD http://www.digip.org/jansson/releases/jansson-2.12.tar.gz jansson-2.12.tar.gz
RUN git clone --depth=1 https://github.com/yaml/libyaml
ADD https://github.com/lz4/lz4/archive/v1.9.2.tar.gz lz4-1.9.2.tar.gz
RUN git clone --depth 1 -b develop https://github.com/madler/zlib.git
RUN git clone --depth=1 https://github.com/catenacyber/fuzzpcap

ADD https://rules.emergingthreats.net/open/suricata/emerging.rules.zip emerging.rules.zip

RUN cargo install --force cbindgen

RUN git clone --depth 1 https://github.com/OISF/suricata.git suricata
RUN git clone --depth 1 --branch master-6.0.x https://github.com/OISF/suricata.git suricata6
RUN git clone --depth 1 https://github.com/OISF/libhtp.git libhtp
RUN git clone --depth 1 https://github.com/OISF/suricata-verify suricata-verify
WORKDIR $SRC
COPY build.sh $SRC/
