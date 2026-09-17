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

FROM gcr.io/oss-fuzz-base/base-builder:ubuntu-24-04

# apache2-dev is needed for the httpd headers and apxs that configure probes for;
# the module's Apache server symbols are stubbed by test/stub.c, so the server
# itself is never linked. The rest are the module's link dependencies, cjose and
# jansson included: those two used to be built from source for instrumentation,
# but that tied the nightly build to their upstream build systems (cjose's main
# branch dropped autotools on 2026-09-12 and every build failed from then on).
# The distro packages are what the module is built and tested against elsewhere.
RUN apt-get update && apt-get install -y --no-install-recommends \
        make autoconf automake libtool pkg-config wget \
        apache2-dev \
        libapr1-dev libaprutil1-dev \
        libcjose-dev libjansson-dev \
        libcurl4-openssl-dev libssl-dev libpcre2-dev \
        zlib1g-dev

RUN git clone --depth=1 https://github.com/OpenIDC/mod_auth_openidc $SRC/mod_auth_openidc
WORKDIR $SRC/mod_auth_openidc
COPY build.sh $SRC/
