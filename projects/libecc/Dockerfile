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

FROM gcr.io/oss-fuzz-base/base-builder@sha256:19782f7fe8092843368894dbc471ce9b30dd6a2813946071a36e8b05f5b1e27e
# ! Project pinned after a clang update and an afl link error. Log: https://oss-fuzz-gcb-logs.storage.googleapis.com/log-bca72181-cfb2-4b2f-98f1-c2addee0aa4b.txt
RUN apt-get update && apt-get install -y make autoconf automake libtool wget python bison flex texinfo lzip bsdmainutils
RUN git clone --depth 1 --branch cryptofuzz https://github.com/libecc/libecc.git
RUN git clone --depth 1 https://github.com/randombit/botan.git
RUN git clone https://github.com/wolfssl/wolfssl
RUN git clone --depth 1 https://github.com/wolfssl/wolfsm
RUN git clone --depth 1 https://github.com/MozillaSecurity/cryptofuzz
RUN wget -q https://ftp.gnu.org/gnu/gmp/gmp-6.2.1.tar.lz
RUN test "$(sha256sum gmp-6.2.1.tar.lz)" = "2c7f4f0d370801b2849c48c9ef3f59553b5f1d3791d070cffb04599f9fc67b41  gmp-6.2.1.tar.lz"
RUN wget -q https://archives.boost.io/release/1.84.0/source/boost_1_84_0.tar.bz2
COPY build.sh $SRC/
