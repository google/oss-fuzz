# Copyright 2019 Google Inc.
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
MAINTAINER sorbet@stripe.com

RUN apt-get install -y curl python ruby libstdc++-5-dev
RUN curl -L -O https://github.com/bazelbuild/bazel/releases/download/0.27.0/bazel-0.27.0-installer-linux-x86_64.sh
RUN chmod a+x bazel-0.27.0-installer-linux-x86_64.sh
RUN bash ./bazel-0.27.0-installer-linux-x86_64.sh

RUN git clone --depth 1 https://github.com/sorbet/sorbet.git /src/sorbet

WORKDIR /src/sorbet
COPY build.sh /src/build.sh
