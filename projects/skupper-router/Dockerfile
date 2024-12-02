################################################################################
# Copyright 2018 Google Inc.
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

# Ensure we work from right python version
RUN apt-get update && apt-get install -y python3.9 python3.9-dev && \
    ln --force -s /usr/bin/python3.9 /usr/local/bin/python3 && \
    apt-get install -y python3-pip libnghttp2-dev
    
# Install libwebsockets library
RUN git clone https://github.com/warmcat/libwebsockets.git --branch v4.2-stable && mkdir libwebsockets/build && cd libwebsockets/build && cmake .. -DLWS_LINK_TESTAPPS_DYNAMIC=ON -DLWS_WITH_LIBUV=OFF -DLWS_WITHOUT_BUILTIN_GETIFADDRS=ON -DLWS_WITHOUT_BUILTIN_SHA1=ON -DLWS_WITH_STATIC=OFF -DLWS_IPV6=ON -DLWS_WITH_HTTP2=OFF -DLWS_WITHOUT_CLIENT=OFF -DLWS_WITHOUT_SERVER=OFF -DLWS_WITHOUT_TESTAPPS=ON -DLWS_WITHOUT_TEST_SERVER=ON -DLWS_WITHOUT_TEST_SERVER_EXTPOLL=ON -DLWS_WITHOUT_TEST_PING=ON -DLWS_WITHOUT_TEST_CLIENT=ON  && make install

# Install qpid-proton library
RUN git clone https://github.com/apache/qpid-proton.git && mkdir qpid-proton/build && cd qpid-proton/build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=OFF -DENABLE_LINKTIME_OPTIMIZATION=OFF -DBUILD_TLS=ON -DSSL_IMPL=openssl -DBUILD_TOOLS=OFF -DBUILD_EXAMPLES=OFF -DBUILD_TESTING=OFF && make install

RUN git clone https://github.com/skupperproject/skupper-router.git && cp skupper-router/tests/fuzz/build.sh $SRC/
