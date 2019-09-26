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

FROM gcr.io/oss-fuzz-base/base-builder
MAINTAINER t-beu@users.sourceforge.net
RUN apt-get update && apt-get install -y make autoconf automake libhdf5-dev libtool zlib1g-dev
ENV HDF5_DIR /usr/lib/x86_64-linux-gnu/hdf5/serial
RUN git clone --depth 1 git://git.code.sf.net/p/matio/matio matio
WORKDIR matio
ADD https://support.hdfgroup.org/ftp/lib-external/szip/2.1.1/src/szip-2.1.1.tar.gz szip.tar.gz
COPY build.sh $SRC/
