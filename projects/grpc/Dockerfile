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

RUN apt-get update && apt-get install -y software-properties-common
RUN apt-get update && apt-get -y install  \
	vim             \
	build-essential \
	openjdk-11-jre-headless   \
	make            \
        curl            \
        autoconf        \
        libtool         \
        rsync

# Install dependencies
RUN apt-get update && apt-get install -y \
    python-all-dev \
    python3-all-dev

# Install Python packages from PyPI
RUN python3 -m pip install --upgrade pip
RUN python3 -m pip install virtualenv
RUN python3 -m pip install incremental futures enum34 protobuf six twisted

RUN git clone --recursive https://github.com/grpc/grpc grpc && \
    cd grpc && \
    git submodule update --init

WORKDIR $SRC/grpc/
COPY build.sh $SRC/
