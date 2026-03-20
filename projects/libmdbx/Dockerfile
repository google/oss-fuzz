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

env MAKE_VERSION 4.4.1

RUN cd $SRC &&\
  curl -L https://ftp.gnu.org/gnu/make/make-$MAKE_VERSION.tar.gz -o make.tar.gz &&\
  tar xf make.tar.gz &&\
  cd make-${MAKE_VERSION} &&\
  ./configure --prefix=$SRC/make-${MAKE_VERSION} &&\
  make -j$(nproc)

#RUN git clone --depth 1 https://github.com/erthink/libmdbx
RUN git clone --depth 1 https://github.com/Segwaz/libmdbx -b fuzz_raw_db_format

COPY build.sh $SRC/

WORKDIR $SRC
