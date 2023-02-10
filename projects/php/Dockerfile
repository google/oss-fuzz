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

# The current clang revision is broken, pin to older one.
FROM gcr.io/oss-fuzz-base/base-builder@sha256:111d6b9d3a52bd3392602c71dc8936c628607a7a9bc86d381db7586f9b1e840f
RUN apt-get update && \
    apt-get install -y autoconf automake libtool bison re2c pkg-config
RUN git clone --depth 1 --branch master https://github.com/php/php-src.git php-src
WORKDIR php-src
COPY build.sh *.options $SRC/
