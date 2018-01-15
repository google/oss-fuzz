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
MAINTAINER jonathan@titanous.com
RUN echo 'deb-src http://archive.ubuntu.com/ubuntu/ xenial main' >> /etc/apt/sources.list &&\
    echo 'deb-src http://archive.ubuntu.com/ubuntu/ xenial-updates main' >> /etc/apt/sources.list &&\
    echo 'deb-src http://security.ubuntu.com/ubuntu/ xenial-security main' >> /etc/apt/sources.list &&\
    apt-get update && apt-get install -y software-properties-common &&\
    add-apt-repository ppa:pitti/systemd-semaphore &&\
    apt-get update && apt-get install -y python3-pip libmount-dev libmount1 &&\
    apt-get build-dep -y systemd &&\
    pip3 install meson ninja
RUN git clone --depth 1 https://github.com/titanous/systemd systemd
WORKDIR systemd
COPY build.sh $SRC/
