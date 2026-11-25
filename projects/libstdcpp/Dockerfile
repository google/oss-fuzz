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

FROM gcr.io/oss-fuzz-base/base-builder:ubuntu-24-04
RUN apt-get update && apt-get install -y make autoconf automake libtool flex bison texinfo libgmp-dev libmpfr-dev libmpc-dev
RUN git clone --depth 1 git://gcc.gnu.org/git/gcc.git libstdcpp
WORKDIR libstdcpp
COPY build.sh $SRC/
ADD https://raw.githubusercontent.com/pauldreik/stdfuzz/main/format/one-arg.cpp $SRC/
