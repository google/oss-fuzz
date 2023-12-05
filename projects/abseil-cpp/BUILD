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

cc_binary(
	name = "string_escape_fuzzer",
	deps = ["@com_google_absl//absl/strings"],
	srcs = ["string_escape_fuzzer.cc"],
)

cc_binary(
	name = "algorithm_fuzzer",
	deps = ["@com_google_absl//absl/algorithm"],
	srcs = ["algorithm_fuzzer.cc"],
)

cc_binary(
	name = "algorithm_container_fuzzer",
	deps = [
        "@com_google_absl//absl/algorithm",
        "@com_google_absl//absl/algorithm:container",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/meta:type_traits"
    ],
	srcs = ["algorithm_container_fuzzer.cc"],
)

cc_binary(
	name = "crc_fuzzer",
	deps = [
        "@com_google_absl//absl/crc:crc32c",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
    ],
	srcs = ["crc_fuzzer.cc"],
)

cc_binary(
	name = "flags_fuzzer",
	deps = [
        "@com_google_absl//absl/flags:commandlineflag",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/flags:config",
        "@com_google_absl//absl/flags:marshalling",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/base:malloc_internal",
        "@com_google_absl//absl/numeric:int128",
        "@com_google_absl//absl/time",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/flags:reflection",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/types:span"
    ],
	srcs = ["flags_fuzzer.cc"],
)

cc_binary(
	name = "ascii_fuzzer",
	deps = ["@com_google_absl//absl/strings"],
	srcs = ["ascii_fuzzer.cc"],
)

cc_binary(
	name = "string_utilities_fuzzer",
	deps = [
		"@com_google_absl//absl/strings",
		"@com_google_absl//absl/strings:cord",
                "@com_google_absl//absl/strings:str_format"
		],
	srcs = ["string_utilities_fuzzer.cc"],
)
