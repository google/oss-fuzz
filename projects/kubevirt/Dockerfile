# Copyright 2024 Google LLC
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
RUN apt update && apt install -y qemu-kvm libvirt-daemon-system
RUN git clone --depth 1 https://github.com/kubevirt/kubevirt
RUN git clone --depth=1 https://github.com/AdamKorcz/go-118-fuzz-build --branch=november-backup
RUN git clone --depth=1 https://github.com/AdamKorcz/kubevirt --branch=fuzz1 $SRC/kubevirt-fuzz1
RUN git clone --depth=1 https://github.com/AdamKorcz/kubevirt --branch=fuzz2 $SRC/kubevirt-fuzz2
RUN git clone --depth=1 https://github.com/AdamKorcz/kubevirt --branch=fuzz3 $SRC/kubevirt-fuzz3
RUN git clone --depth=1 https://github.com/AdamKorcz/kubevirt --branch=fuzz4 $SRC/kubevirt-fuzz4
RUN git clone --depth=1 https://github.com/AdamKorcz/kubevirt --branch=fuzz5 $SRC/kubevirt-fuzz5
RUN git clone --depth=1 https://github.com/AdamKorcz/kubevirt --branch=fuzz6 $SRC/kubevirt-fuzz6
RUN git clone --depth=1 https://github.com/AdamKorcz/kubevirt --branch=fuzz7 $SRC/kubevirt-fuzz7
COPY build.sh fuzz*test.go *.options $SRC/
WORKDIR $SRC/kubevirt
