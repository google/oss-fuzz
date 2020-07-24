
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
MAINTAINER miller.lucas@gmail.com

RUN apt-get update && apt-get install -y build-essential zlib1g-dev python make openexr automake openexr-viewers libopenexr-dev libilmbase-dev wget

# Install cmake version 3.14
RUN wget https://github.com/Kitware/CMake/releases/download/v3.14.5/cmake-3.14.5-Linux-x86_64.sh; \
    chmod +x cmake-3.14.5-Linux-x86_64.sh; \
    ./cmake-3.14.5-Linux-x86_64.sh --skip-license --prefix="/usr/local"

RUN wget http://download.savannah.nongnu.org/releases/openexr/ilmbase-2.2.0.tar.gz
RUN tar xvfz ilmbase-2.2.0.tar.gz && cd ilmbase-2.2.0 && ./configure && make -j6 install

RUN wget http://download.savannah.nongnu.org/releases/openexr/openexr-2.2.0.tar.gz
RUN tar xvfz openexr-2.2.0.tar.gz && cd openexr-2.2.0 && ./configure --disable-ilmbasetest && make -j6 install

# Install OpenEXR
#RUN wget http://download.savannah.nongnu.org/releases/openexr/ilmbase-2.2.0.tar.gz
#RUN tar xvfz ilmbase-2.2.0.tar.gz && cd ilmbase-2.2.0 && ./configure && make -j6 install
#RUN git clone --depth 1 https://github.com/AcademySoftwareFoundation/openexr.git

RUN git clone --depth 1 https://github.com/alembic/alembic
# WORKDIR alembic
COPY build.sh *.h *.cc $SRC/
