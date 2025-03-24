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
ARG project_workdir
ARG runtime_image
ARG OUT
ARG ENV
ARG FUZZING_LANGUAGE

FROM $build_image AS project_fuzzer_build
ARG OUT
ARG project_workdir
ARG ENV
ARG FUZZING_LANGUAGE

RUN echo "1"
RUN echo "$OUT"
RUN echo "$project_workdir"
RUN echo "$ENV"
RUN echo "$FUZZING_LANGUAGE"
RUN ls -al /
RUN ls -al /src
RUN ls -al /work

RUN python3 -c "import json, os; \
    env_string_list = json.loads(os.environ['ENV']); \
    env_dict = dict(item.split('=') for item in env_string_list); \
    [os.environ.setdefault(k, v) for k, v in env_dict.items()]"

RUN echo "2"
RUN echo "$OUT"
RUN echo "$project_workdir"

RUN rm -rf /out && cd /src && cd $project_workdir && \
    mkdir -p $OUT && compile && \
    echo "\n\n" && ls / && echo "\n\n" && ls /workspace

FROM $runtime_image

ARG OUT
ARG fuzzbench_run_fuzzer_path

RUN echo "3"
RUN echo $OUT
RUN ls -al /
RUN ls -al /home
RUN ls -al /fuzzbench

COPY --from=project_fuzzer_build $OUT $OUT/
COPY --from=project_fuzzer_build $fuzzbench_run_fuzzer_path /usr/local/bin/fuzzbench_run_fuzzer.sh

RUN echo "4"
RUN echo $OUT
RUN ls -al $OUT

WORKDIR $OUT

RUN echo "4"
RUN echo $OUT
RUN ls -al $OUT
RUN ls -al ./
RUN ls -al /
CMD ["bash", "-c", "ls /fuzzbench && cd $OUT && ls $OUT && fuzzbench_run_fuzzer"]