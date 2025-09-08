# Copyright 2025 Google LLC
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

FROM gcr.io/oss-fuzz-base/base-builder:ubuntu-20-04

# Copy/Run this now to make the cache more resilient.
COPY fuzzbench_install_dependencies_ubuntu_20_04 /usr/local/bin
RUN fuzzbench_install_dependencies_ubuntu_20_04

ENV OSS_FUZZ_ON_DEMAND=1

COPY fuzzbench_build fuzzbench_run_fuzzer fuzzbench_measure /usr/local/bin/