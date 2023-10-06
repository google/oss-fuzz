# Copyright 2021 Google LLC
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

FROM gcr.io/oss-fuzz-base/base-builder-go
RUN apt-get update && apt-get install -y wget zip
RUN git clone --depth 1 https://github.com/argoproj/argo-cd
RUN git clone --depth 1 https://github.com/argoproj/argo-workflows
RUN git clone --depth 1 https://github.com/argoproj/argo-events
RUN git clone --depth 1 https://github.com/argoproj/gitops-engine
RUN git clone --depth 1 https://github.com/argoproj/argo-rollouts
RUN git clone --depth 1 https://github.com/cncf/cncf-fuzzing
RUN wget https://github.com/facebook/zstd/releases/download/v1.4.2/zstd-1.4.2.tar.gz && \
    tar xzf zstd-1.4.2.tar.gz && \
    cd zstd-1.4.2 && \
    export CC=clang && \
    export CXX=clang++ && \
    export CXXFLAGS="-stdlib=libc++" && \
    make -j$(nproc)
COPY build.sh $SRC/
WORKDIR $SRC/argo-cd
