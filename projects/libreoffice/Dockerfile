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
# enable source repos
RUN sed -i -e '/^#\s*deb-src.*\smain\s\+restricted/s/^#//' /etc/apt/sources.list
#build requirements
RUN apt-get update && apt-get build-dep -y libreoffice
RUN apt-get install -y lockfile-progs wget yasm locales && locale-gen en_US.UTF-8

#clone source
RUN git clone --depth 1 https://git.libreoffice.org/core libreoffice
WORKDIR libreoffice
RUN ./bin/oss-fuzz-setup.sh
COPY build.sh $SRC/
