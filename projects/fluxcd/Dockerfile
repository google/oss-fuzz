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
RUN apt-get update && apt-get install -y wget zlib1g-dev pkg-config
RUN git clone --depth 1 --branch fuzz1 https://github.com/AdamKorcz/kustomize-controller
RUN git clone --depth 1 --branch fuzz1 https://github.com/AdamKorcz/pkg
RUN git clone --depth 1 --branch fuzz1 https://github.com/AdamKorcz/notification-controller

# Go 1.16 is needed to build the notification-controller
RUN cd /tmp \
	&& wget https://golang.org/dl/go1.16.8.linux-amd64.tar.gz \
	&& tar -xf go1.16.8.linux-amd64.tar.gz

COPY build.sh $SRC/
WORKDIR $SRC
