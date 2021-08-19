# Copyright 2021 Google LLC
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

RUN apt-get update -y \
    && env DEBIAN_FRONTEND=noninteractive \
        apt-get install --yes --no-install-recommends \
            bash \
            wget \
            curl \
            ccache \
	        expect \
            ninja-build \
            perl \
            pkg-config \
            python \
            python-lxml \
            python-requests \
            python-termcolor \
            sudo \
            tzdata


RUN wget https://github.com/Kitware/CMake/releases/download/v3.21.1/cmake-3.21.1-Linux-x86_64.sh; \
    chmod +x cmake-3.21.1-Linux-x86_64.sh; \
    ./cmake-3.21.1-Linux-x86_64.sh --skip-license --prefix="/usr"

RUN git clone --recursive https://github.com/ClickHouse/ClickHouse $SRC/ClickHouse
WORKDIR $SRC/ClickHouse

COPY build.sh $SRC/
