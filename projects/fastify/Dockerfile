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

FROM gcr.io/oss-fuzz-base/base-builder-javascript

COPY build.sh $SRC/

RUN git clone --depth 1 https://github.com/fastify/fastify fastify
RUN git clone --depth 1 https://github.com/fastify/fast-json-stringify fast-json-stringify
RUN git clone --depth 1 https://github.com/fastify/fastify-jwt fastify-jwt
RUN git clone --depth 1 https://github.com/fastify/fastify-response-validation fastify-response-validation
RUN git clone --depth 1 https://github.com/fastify/fastify-auth fastify-auth
RUN git clone --depth 1 https://github.com/fastify/fastify-basic-auth fastify-basic-auth
RUN git clone --depth 1 https://github.com/fastify/fastify-bearer-auth fastify-bearer-auth
RUN git clone --depth 1 http://github.com/fastify/fastify-plugin fastify-plugin
RUN git clone --depth 1 http://github.com/fastify/fastify-cookie fastify-cookie
RUN git clone --depth 1 http://github.com/fastify/fastify-cors fastify-cors
RUN git clone --depth 1 http://github.com/fastify/fastify-secure-session fastify-secure-session

RUN git clone --depth 1 https://github.com/AdaLogics/ada-fuzzers fuzzers

WORKDIR $SRC/fastify
