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

RUN apt-get update && apt-get install -y make autoconf automake autopoint libtool pkg-config

RUN git clone --depth 1 https://github.com/libyal/libfwnt.git libfwnt
RUN git clone --depth 1 https://github.com/libyal/libfwsi.git libfwsi

RUN git clone --depth 1 https://github.com/libyal/libesedb.git libesedb
RUN git clone --depth 1 https://github.com/libyal/libevt.git libevt
RUN git clone --depth 1 https://github.com/libyal/libevtx.git libevtx
RUN git clone --depth 1 https://github.com/libyal/libexe.git libexe
RUN git clone --depth 1 https://github.com/libyal/liblnk.git liblnk
RUN git clone --depth 1 https://github.com/libyal/libmsiecf.git libmsiecf
RUN git clone --depth 1 https://github.com/libyal/libolecf.git libolecf
RUN git clone --depth 1 https://github.com/libyal/libregf.git libregf
RUN git clone --depth 1 https://github.com/libyal/libscca.git libscca

WORKDIR libyal
COPY build.sh $SRC/
