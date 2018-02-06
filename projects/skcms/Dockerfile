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
MAINTAINER kjlubick@chromium.org

# Can't use apt-get install cmake, it installs 3.5.0, which is too old
#RUN apt-get update && apt-get install -y wget

#RUN wget -O $TMP/installcmake.sh https://cmake.org/files/v3.10/cmake-3.10.1-Linux-x86_64.sh
#RUN chmod 755 $TMP/installcmake.sh
#RUN mkdir -p 777 /opt/cmake
#RUN $TMP/installcmake.sh --skip-license --prefix=/opt/cmake

# checkout all sources needed to build your project
RUN git clone https://skia.googlesource.com/skcms.git

# current directory for build script
WORKDIR skcms

COPY build.sh $SRC/

COPY iccprofile_parse.c $SRC/skcms/
COPY iccprofile_parse.options $SRC/skcms/