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
    make \
    autoconf \
    automake \
    libtool \
    groff-base \
    libssl-dev \
    libsasl2-dev \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/openldap/openldap $SRC/openldap

COPY build.sh \
     fuzz_ldap_dn.c \
     fuzz_ldap_filter.c \
     fuzz_ldap_url.c \
     fuzz_ldap_dn.dict \
     fuzz_ldap_filter.dict \
     fuzz_ldap_url.dict \
     $SRC/

WORKDIR $SRC/openldap
