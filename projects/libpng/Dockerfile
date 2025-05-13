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
    apt-get install -y make autoconf automake libtool zlib1g-dev

RUN git clone --depth 1 https://github.com/madler/zlib.git
# RUN git clone --depth 50 https://github.com/pnggroup/libpng.git
RUN git clone --depth 1 https://github.com/VladimirHaninEPFL/libpng
# RUN git clone --depth 1 https://github.com/cristiano-masutti/libpng

RUN cp libpng/contrib/oss-fuzz/build.sh $SRC
WORKDIR libpng

# REMOVE TIHS FOR OTHER REPOS
# RUN git checkout 98448e372d717206c9f5a2a39d42e7417e6889cb
