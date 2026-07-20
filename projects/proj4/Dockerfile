# Copyright 2016 Google Inc.
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
    apt-get install -y make autoconf automake libtool g++ sqlite3 pkg-config wget

RUN git clone --depth 1 https://github.com/OSGeo/PROJ PROJ

# Pin to 8.17.0 as later versions require openssl 3.0 that Ubuntu 20.04 doesn't provide
RUN git clone --depth 1 --branch curl-8_17_0 https://github.com/curl/curl.git PROJ/curl

# Pin to v4.7.1 as latest libtiff master requires autoconf 2.71
RUN git clone --depth 1 --branch v4.7.1 https://gitlab.com/libtiff/libtiff.git PROJ/libtiff

WORKDIR PROJ

RUN cp test/fuzzers/build.sh $SRC/
