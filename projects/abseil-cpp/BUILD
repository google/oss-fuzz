# Copyright 2020 Google Inc.
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

load("@rules_fuzzing//fuzzing:cc_defs.bzl", "cc_fuzz_test")

cc_fuzz_test(
    name = "string_escape_fuzzer",
    srcs = ["string_escape_fuzzer.cc"],
    deps = ["@com_google_absl//absl/strings"],
)

cc_fuzz_test(
    name = "string_utilities_fuzzer",
    srcs = ["string_utilities_fuzzer.cc"],
    deps = [
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:cord",
        "@com_google_absl//absl/strings:str_format",
        # The below are added for OSS-Fuzz-gen purposes. The goal is to make
        # a general build rule from which we can build harnesses targeting
        # most of the abseil-cpp codebase.
        "@com_google_absl//absl/algorithm:algorithm",
        "@com_google_absl//absl/hash:hash",
        "@com_google_absl//absl/crc:crc32c",
        "@com_google_absl//absl/time:time",
        "@com_google_absl//absl/base:base",
    ],
)
