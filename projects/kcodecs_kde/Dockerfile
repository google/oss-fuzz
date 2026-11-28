FROM fedora:38
# Copyright 2025 Google LLC
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
###########################################################################
RUN dnf update -y && dnf install -y \
    clang \
    clang-tools-extra \
    llvm-libs \
    cmake \
    git \
    make \
    gcc \
    gcc-c++ \
    libstdc++-devel \
    libasan \
    libubsan \
    kf5-kcodecs-devel \
    qt5-qtbase-devel \
    qt5-qtxmlpatterns-devel \
    pkgconfig \
    findutils
WORKDIR /src
COPY build.sh /src/
COPY kcodecs_fuzzer.cc /src/
COPY corpus.tar.gz /src/
ENV FUZZER_NAME=kcodecs_fuzzer
RUN chmod +x build.sh
RUN bash build.sh
# ENTRYPOINT ["./build.sh"]
