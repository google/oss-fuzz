# Copyright 2023 Google LLC
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

FROM gcr.io/oss-fuzz-base/base-builder-python
RUN apt-get update && \
        DEBIAN_FRONTEND=noninteractive apt-get install -y python3.9 python3-pip && \
        rm -rf /var/lib/apt/lists/*
RUN python3.9 -m pip install --upgrade pip
RUN git clone https://github.com/angr/archinfo.git archinfo
RUN git clone --recursive https://github.com/angr/pyvex.git pyvex
RUN cp pyvex/fuzzing/build.sh $SRC/
WORKDIR $SRC/pyvex
