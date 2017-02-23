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

FROM ossfuzz/base-builder
MAINTAINER alex.gaynor@gmail.com
RUN apt-get install -y cmake zlib1g-dev libssl-dev

# Can't use --depth=1 because git.libssh.org is using the "dumb" HTTP
# transport, which doesn't support it.
RUN git clone https://git.libssh.org/projects/libssh.git

WORKDIR libssh
COPY build.sh libssh_server_fuzzer.cc $SRC/
