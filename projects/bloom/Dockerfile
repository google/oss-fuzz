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

FROM gcr.io/oss-fuzz-base/base-builder-go
# TODO(@silvergasp): Switch this back to bits-and-blooms
#RUN git clone --depth 1 https://github.com/bits-and-blooms/bloom.git  bloom
RUN git clone --depth 1 https://github.com/silvergasp/bloom.git  bloom
RUN cp bloom/fuzz/build.sh $SRC/
WORKDIR bloom
RUN go install github.com/AdamKorcz/go-118-fuzz-build@latest
RUN go get github.com/AdamKorcz/go-118-fuzz-build/testing
