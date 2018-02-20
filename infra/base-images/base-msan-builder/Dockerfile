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

FROM gcr.io/oss-fuzz-base/base-clang
MAINTAINER ochang@google.com
RUN sed -i -r 's/#\s*deb-src/deb-src/g' /etc/apt/sources.list
RUN apt-get update && apt-get install -y python dpkg-dev patchelf python-apt zip

# Take all libraries from lib/msan
RUN cp -R /usr/msan/lib/* /usr/lib/

COPY compiler_wrapper.py msan_build.py patch_build.py wrapper_utils.py /usr/local/bin/
COPY packages /usr/local/bin/packages

RUN mkdir /msan
WORKDIR /msan
