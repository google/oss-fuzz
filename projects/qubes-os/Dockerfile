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
MAINTAINER paras.chetal@gmail.com

RUN apt-get update && apt-get -y install build-essential automake libtool git python

WORKDIR qubes-os

RUN git clone --depth 1 https://github.com/qubesos/qubes-builder-debian.git $SRC/qubes-os/builder-debian && \
    echo "deb [arch=amd64] http://deb.qubes-os.org/r4.0/vm stretch main" >> /etc/apt/sources.list && \
    echo "deb [arch=amd64] http://deb.qubes-os.org/r4.0/vm stretch-testing main" >> /etc/apt/sources.list && \
    apt-key add $SRC/qubes-os/builder-debian/keys/qubes-debian-r4.0.asc && \
    apt-get update

RUN git clone -b fuzz --single-branch https://github.com/paraschetal/qubes-linux-utils.git $SRC/qubes-os/linux-utils  && \
    $SRC/qubes-os/builder-debian/scripts/debian-parser control --build-depends $SRC/qubes-os/linux-utils/debian/control | xargs apt-get -y install && \
    $SRC/qubes-os/builder-debian/scripts/debian-parser control --qubes-build-depends debian $SRC/qubes-os/linux-utils/debian/control | xargs apt-get -y install && \
    $SRC/qubes-os/builder-debian/scripts/debian-parser control --qubes-build-depends stretch $SRC/qubes-os/linux-utils/debian/control | xargs apt-get -y install

COPY build.sh *.options $SRC/
