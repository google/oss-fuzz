# Copyright 2019 Google Inc.
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
RUN apt-get update && apt-get install -y python3-pip git wget
RUN python3 -m pip install --upgrade pip
RUN pip3 install protobuf grpcio-tools scons
RUN update-alternatives --install /usr/bin/python python $(which python3) 100
RUN git clone --depth 1 https://github.com/nanopb/nanopb $SRC/nanopb
COPY build.sh $SRC/

