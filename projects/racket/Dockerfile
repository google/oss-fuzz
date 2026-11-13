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
RUN apt-get update && apt-get install -y libncurses-dev zlib1g-dev
# TODO: switch to racket/racket once coverage counters and the fasl
# repair are merged there
RUN git clone --depth 1 --branch fuzzing-support https://github.com/samth/racket racket
# portable-bytecode boot files, so that Chez Scheme builds without an
# existing Racket or Chez Scheme
RUN make -C racket pb-fetch
WORKDIR $SRC/racket
COPY build.sh $SRC/
COPY driver.c embed-data.S *.rkt $SRC/racket-fuzz/
