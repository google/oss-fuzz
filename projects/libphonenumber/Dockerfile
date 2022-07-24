# Copyright 2020 Google Inc.
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

RUN apt-get update && apt-get install -y autoconf automake \
      cmake cmake-curses-gui libre2-dev \
      libicu-dev libboost-dev libboost-thread-dev libboost-system-dev \
      libgflags-dev libgoogle-glog-dev libssl-dev \
      protobuf-compiler libtool wget default-jre icu-devtools
RUN apt-get install -y libgtest-dev && \
    cd /usr/src/googletest/googletest && \
		mkdir build && \
		cd build && \
		cmake .. && \
		make && \
		mkdir /usr/local/lib/googletest && \
		ln -sn /usr/local/lib/googletest/libgtest.a /usr/lib/libgtest.a && \
		ln -sn /usr/local/lib/googletest/libgtest_main.a /usr/lib/libgtest_main.a && \
    rm /lib/x86_64-linux-gnu/libgtest.a && \
    ln -sn /usr/local/lib/googletest/libgtest.a /lib/x86_64-linux-gnu/libgtest.a
RUN wget https://github.com/unicode-org/icu/releases/download/release-66-rc/icu4c-66rc-src.tgz && \
    tar xzvf icu4c-66rc-src.tgz
RUN git clone https://github.com/google/libphonenumber

COPY build.sh $SRC/
