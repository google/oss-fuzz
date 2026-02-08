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
    make autoconf automake libtool pkg-config \
    libz-dev libssl-dev liblz4-dev libzstd-dev libxxhash-dev \
    libpopt-dev
RUN git clone --depth 1 https://github.com/RsyncProject/rsync rsync
WORKDIR rsync
COPY build.sh fuzz_wildmatch.c fuzz_parse_filter.c fuzz_rsyncd_conf.c \
     fuzz_parse_filter.options \
     wildmatch.dict filter_rules.dict rsyncd_conf.dict $SRC/
