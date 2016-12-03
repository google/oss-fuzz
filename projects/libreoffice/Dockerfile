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

FROM ossfuzz/base-libfuzzer
MAINTAINER security@documentfoundation.org
RUN apt-get -y build-dep libreoffice
RUN apt-get -y install wget

RUN git clone --depth 1 git://anongit.freedesktop.org/libreoffice/core libreoffice
RUN wget http://dev-www.libreoffice.org/corpus/wmffuzzer_seed_corpus.zip
WORKDIR libreoffice
COPY build.sh fonts.conf $SRC/
