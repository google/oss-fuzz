#!/usr/bin/env python3
#
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
ARG build_image
ARG runtime_image
ARG OUT
ARG fuzzbench_run_fuzzer_path

FROM $build_image AS project_fuzzer_build

FROM $runtime_image

COPY --from=project_fuzzer_build $OUT $OUT/
COPY --from=project_fuzzer_build $fuzzbench_run_fuzzer_path /usr/local/bin/fuzzbench_run_fuzzer.sh

WORKDIR $OUT
CMD ["bash", "-c", "ls /fuzzbench && cd $OUT && ls $OUT && fuzzbench_run_fuzzer"]