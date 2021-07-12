# Copyright 2021 Google Inc.
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
RUN apt-get update && apt-get install -y make autoconf automake build-essential 
RUN git clone --depth 1 https://github.com/ansible/ansible
RUN git clone --depth=1 https://github.com/yaml/libyaml
#RUN zip $OUT/load_list_of_tasks_fuzzer_seed_corpus.zip $SRC/libyaml/examples/*
WORKDIR ansible
COPY build.sh split_args_fuzzer.py load_list_of_tasks_fuzzer.py $SRC/
COPY config_files/ansible_builtin_runtime_yml.py config_files/base_yml.py $SRC/
