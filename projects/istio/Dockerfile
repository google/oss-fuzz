# Copyright 2020 Google Inc.
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

# Setup the builder for Istio. The standard Go builder is sufficient.
FROM gcr.io/oss-fuzz-base/base-builder-go
RUN git clone --depth 1 https://github.com/istio/istio
RUN wget https://go.dev/dl/go1.20.2.linux-amd64.tar.gz \
    && mkdir temp-go \
    && rm -rf /root/.go/* \
    && tar -C temp-go/ -xzf go1.20.2.linux-amd64.tar.gz \
    && mv temp-go/go/* /root/.go/
COPY build.sh $SRC/
WORKDIR $SRC/istio
