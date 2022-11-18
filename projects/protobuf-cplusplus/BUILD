# Copyright 2022 Google Inc.
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
    name = "fuzz_pb2",
    deps = [
        ":protobuf",
        ":cc_test_messages_proto2_proto",
    ],
    srcs = ["fuzz/fuzz_pb2.cc"],
)

cc_fuzz_test(
    name = "fuzz_pb3",
    deps = [
        ":protobuf",
        ":cc_test_messages_proto3_proto",
    ],
    srcs = ["fuzz/fuzz_pb3.cc"],
)

cc_fuzz_test(
    name = "fuzz_json2",
    deps = [
        ":protobuf",
        ":cc_test_messages_proto2_proto",
    ],
    srcs = ["fuzz/fuzz_json2.cc"],
)

cc_fuzz_test(
    name = "fuzz_json3",
    deps = [
        ":protobuf",
        ":cc_test_messages_proto3_proto",
    ],
    srcs = ["fuzz/fuzz_json3.cc"],
)

cc_fuzz_test(
    name = "fuzz_text2",
    deps = [
        ":protobuf",
        ":cc_test_messages_proto2_proto",
    ],
    srcs = ["fuzz/fuzz_text2.cc"],
)

cc_fuzz_test(
    name = "fuzz_text3",
    deps = [
        ":protobuf",
        ":cc_test_messages_proto3_proto",
    ],
    srcs = ["fuzz/fuzz_text3.cc"],
)

cc_proto_library(
    name = "cc_test_messages_proto2_proto",
    deps = [":test_messages_proto2_proto"],
)

cc_proto_library(
    name = "cc_test_messages_proto3_proto",
    deps = [":test_messages_proto3_proto"],
)
