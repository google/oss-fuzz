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

RUN apt update && apt install -y build-essential binutils-dev libunwind-dev libblocksruntime-dev liblzma-dev
RUN cargo install honggfuzz

#TODO back to main repo
RUN git clone --depth 1 --branch ossfuzz https://github.com/catenacyber/tikv.git

RUN cd $SRC/tikv/fuzz && cargo build

COPY build.sh $SRC/

WORKDIR $SRC/tikv
