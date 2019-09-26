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
MAINTAINER tsdgeos@gmail.com
RUN apt-get install --yes cmake
RUN git clone --depth 1 https://github.com/madler/zlib.git
RUN git clone --depth 1 https://github.com/nih-at/libzip.git
RUN git clone --depth 1 git://anongit.kde.org/extra-cmake-modules
RUN git clone --depth 1 --branch=5.15 git://code.qt.io/qt/qtbase.git
RUN git clone --depth 1 git://anongit.kde.org/karchive
RUN git clone --depth 1 git://anongit.kde.org/kimageformats
COPY build.sh $SRC
COPY kimgio_fuzzer.cc $SRC
WORKDIR kimageformats



