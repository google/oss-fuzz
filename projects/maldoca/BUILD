load("@rules_fuzzing//fuzzing:cc_defs.bzl", "cc_fuzz_test")
load("@rules_proto//proto:defs.bzl", "proto_library")

cc_fuzz_test(
	name = "fuzz_process_doc",
	deps = [
        "@com_google_absl//absl/strings",
        "//maldoca/service/proto:doc_type_cc_proto",
        "//maldoca/service/proto:processing_config_cc_proto",
        "//maldoca/service:process_doc"
    ],
	srcs = ["fuzz_process_doc.cc"],
)
