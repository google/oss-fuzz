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

FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && apt-get install -y \
	build-essential ninja-build cmake make \
	libreadline-dev libunwind-dev zlib1g-dev

RUN git clone --recursive https://github.com/ligurio/lua-c-api-tests testdir
WORKDIR $SRC/testdir
RUN git clone --depth 1 --jobs $(nproc) https://github.com/ligurio/lua-c-api-corpus corpus_dir
COPY build.sh $SRC
