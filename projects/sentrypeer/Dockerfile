# Copyright 2026 Google LLC
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
    autoconf automake autoconf-archive libtool pkg-config make \
    libsqlite3-dev uuid-dev libcurl4-openssl-dev libjansson-dev \
    libmicrohttpd-dev libpcre2-dev

# libosip2 is built from source in build.sh so it gets the fuzzing sanitizers.
RUN git clone --depth 1 https://git.savannah.gnu.org/git/osip.git osip
RUN git clone --depth 1 https://github.com/SentryPeer/SentryPeer.git sentrypeer

WORKDIR $SRC/sentrypeer
COPY build.sh fuzz_sip_parser.c fuzz_http_input.c fuzz_json_bad_actor.c sip.dict $SRC/
