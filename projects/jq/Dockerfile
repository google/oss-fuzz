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
MAINTAINER adam@adalogics.com
RUN apt-get update && apt-get install -y make cmake flex bison libtool automake autoconf

RUN git clone --depth 1 https://github.com/stedolan/jq
WORKDIR $SRC/jq

COPY build.sh $SRC/
COPY jq_fuzz_parse.c $SRC/jq/jq_fuzz_parse.c
