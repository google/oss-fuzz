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

FROM gcr.io/oss-fuzz-base/base-builder
RUN GO111MODULE=on go get gvisor.dev/gvisor/runsc@go
RUN mv $GOPATH/pkg/mod/gvisor.dev/* $GOPATH/pkg/mod/gvisor.dev/gvisor
COPY build.sh buffer_fuzzer.go $SRC/
ENV GVISOR_ROOT "/root/go/pkg/mod/gvisor.dev/gvisor"
WORKDIR $GVISOR_ROOT
