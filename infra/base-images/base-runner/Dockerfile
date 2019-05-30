# Copyright 2016 Google Inc.
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

FROM gcr.io/oss-fuzz-base/base-image
MAINTAINER mike.aizatsky@gmail.com
RUN apt-get install -y \
    binutils \
    file \
    fonts-dejavu \
    git \
    libblocksruntime0 \
    libc6-dev-i386 \
    libcap2 \
    libunwind8 \
    python3 \
    python3-pip \
    wget \
    zip

RUN git clone https://chromium.googlesource.com/chromium/src/tools/code_coverage /opt/code_coverage
RUN pip3 install -r /opt/code_coverage/requirements.txt

COPY bad_build_check \
    coverage \
    coverage_helper \
    download_corpus \
    llvm-cov \
    llvm-profdata \
    llvm-symbolizer \
    minijail0 \
    reproduce \
    run_fuzzer \
    run_minijail \
    targets_list \
    test_all \
    /usr/local/bin/

# Default environment options for various sanitizers.
# Note that these match the settings used in ClusterFuzz and
# shouldn't be changed unless a corresponding change is made on
# ClusterFuzz side as well.
ENV ASAN_OPTIONS="alloc_dealloc_mismatch=0:allocator_may_return_null=1:allocator_release_to_os_interval_ms=500:check_malloc_usable_size=0:detect_container_overflow=1:detect_odr_violation=0:detect_leaks=1:detect_stack_use_after_return=1:fast_unwind_on_fatal=0:handle_abort=1:handle_segv=1:handle_sigill=1:max_uar_stack_size_log=16:print_scariness=1:quarantine_size_mb=10:strict_memcmp=1:strip_path_prefix=/workspace/:symbolize=1:use_sigaltstack=1"
ENV MSAN_OPTIONS="print_stats=1:strip_path_prefix=/workspace/:symbolize=1"
ENV UBSAN_OPTIONS="print_stacktrace=1:print_summary=1:silence_unsigned_overflow=1:strip_path_prefix=/workspace/:symbolize=1"
ENV FUZZER_ARGS="-rss_limit_mb=2048 -timeout=25"
ENV AFL_FUZZER_ARGS="-m none"
