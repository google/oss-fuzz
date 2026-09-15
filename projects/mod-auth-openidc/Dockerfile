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
# itself is never linked. The rest are the module's link dependencies.
RUN apt-get update && apt-get install -y --no-install-recommends \
        make autoconf automake libtool pkg-config wget \
        apache2-dev \
        libapr1-dev libaprutil1-dev \
        libcurl4-openssl-dev libssl-dev libpcre2-dev \
        zlib1g-dev

# jansson and cjose sit directly on the JSON/JOSE parse paths that fuzz_json and
# fuzz_jwt drive, so both are built from source under $CFLAGS rather than taken
# from the distro -- otherwise the sanitizers see nothing inside them and the
# coverage report stops at the library boundary. cjose is not itself an OSS-Fuzz
# project, so this is the only instrumented build it gets.
RUN git clone --depth=1 https://github.com/akheron/jansson $SRC/jansson
RUN git clone --depth=1 https://github.com/OpenIDC/cjose $SRC/cjose

RUN git clone --depth=1 https://github.com/OpenIDC/mod_auth_openidc $SRC/mod_auth_openidc
WORKDIR $SRC/mod_auth_openidc
COPY build.sh $SRC/
