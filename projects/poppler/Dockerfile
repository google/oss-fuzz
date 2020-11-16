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

#ADD focal.list /etc/apt/sources.list.d/focal.list
#ADD extra_cmake_apt.pin /etc/apt/preferences
#RUN sed -i -e 's/xenial/focal/g' /etc/apt/sources.list

FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && apt-get install -y autoconf make libtool libglib2.0-dev libgirepository1.0-dev libcairo2-dev libgcc-5-dev qtbase5-dev
RUN git clone --depth 1 --single-branch --branch fuzzing https://gitlab.freedesktop.org/ceyhunalp/poppler.git
RUN git clone --depth 1 git://git.sv.nongnu.org/freetype/freetype2.git
RUN git clone --depth 1 https://github.com/mm2/Little-CMS.git
RUN git clone --depth 1 https://github.com/uclouvain/openjpeg
RUN git clone --depth 1 https://github.com/madler/zlib.git
RUN git clone --depth 1 https://github.com/glennrp/libpng.git
RUN git clone --depth 1 https://github.com/mozilla/pdf.js pdf.js && \
    zip -q $SRC/poppler_seed_corpus.zip pdf.js/test/pdfs/*.pdf && \
    rm -rf pdf.js
ADD https://raw.githubusercontent.com/google/fuzzing/master/dictionaries/pdf.dict $SRC/poppler.dict
WORKDIR $SRC/poppler
COPY build.sh $SRC/
