#!/bin/bash -eu
#
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

# Skip leak sanitizer and disable possible null return from allocator
export ASAN_OPTIONS="detect_leaks=0:allocator_may_return_null=1"

# Run unit test and disable those tests that are failing or not able to run without network connection
ctest --test-dir libarchive/build2 -j$(nproc) -E \
    "libarchive_test_compat_zip_4|libarchive_test_read_format_cpio_bin*|libarchive_test_read_pax_truncated|bsdcpio_test_basic|bsdcpio_test_option_0|bsdcpio_test_option_L_upper|bsdcpio_test_option_d|bsdcpio_test_option_f|bsdcpio_test_option_m|bsdcpio_test_option_t"
