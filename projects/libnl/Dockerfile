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
################################################################################

FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && apt-get install -y \
    autoconf automake libtool pkg-config make bison flex
RUN git clone --depth 1 https://github.com/thom311/libnl.git libnl
WORKDIR $SRC
COPY build.sh fuzz_msg.c fuzz_attr.c fuzz_addr.c fuzz_route.c \
     fuzz_neigh.c fuzz_ct.c fuzz_idiag.c $SRC/
