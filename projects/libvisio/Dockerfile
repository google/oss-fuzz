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

FROM gcr.io/oss-fuzz-base/base-builder
MAINTAINER dtardon@redhat.com
# build requirements
RUN apt-get update
RUN apt-get build-dep -y libvisio librevenge
RUN apt-get install -y liblzma-dev
# clone source
RUN git clone --depth 1 git://gerrit.libreoffice.org/libvisio
RUN git clone --depth 1 git://git.code.sf.net/p/libwpd/librevenge libvisio/librevenge
ADD https://dev-www.libreoffice.org/corpus/vsdfuzzer_seed_corpus.zip $SRC/
WORKDIR libvisio
COPY build.sh $SRC/
