#!/bin/bash -eu
# Copyright 2026 Google LLC
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

src_dir="$SRC/cpace"
build_dir="$WORK/cpace-build"
rm -rf "$build_dir"
mkdir -p "$build_dir"
cp -a "$src_dir"/. "$build_dir"/
cd "$build_dir"

go install github.com/AdamKorcz/go-118-fuzz-build@latest
go get github.com/AdamKorcz/go-118-fuzz-build/testing

compile_native_go_fuzzer github.com/the-sarge/cpace FuzzDecodeMessageA fuzz_decode_message_a
compile_native_go_fuzzer github.com/the-sarge/cpace FuzzDecodeMessageB fuzz_decode_message_b
compile_native_go_fuzzer github.com/the-sarge/cpace FuzzDecodeMessageC fuzz_decode_message_c
compile_native_go_fuzzer github.com/the-sarge/cpace FuzzDraftVectorJSONLoader fuzz_draft_vector_json_loader
compile_native_go_fuzzer github.com/the-sarge/cpace FuzzDraftInvalidVectorJSONLoader fuzz_draft_invalid_vector_json_loader
compile_native_go_fuzzer github.com/the-sarge/cpace FuzzProtocolConsistency fuzz_protocol_consistency
compile_native_go_fuzzer github.com/the-sarge/cpace FuzzProtocolMismatch fuzz_protocol_mismatch
compile_native_go_fuzzer github.com/the-sarge/cpace FuzzRespondWithFuzzedMessageA fuzz_respond_with_fuzzed_message_a
compile_native_go_fuzzer github.com/the-sarge/cpace FuzzInitiatorFinishWithFuzzedMessageB fuzz_initiator_finish_with_fuzzed_message_b
compile_native_go_fuzzer github.com/the-sarge/cpace FuzzResponderFinishWithFuzzedMessageC fuzz_responder_finish_with_fuzzed_message_c
compile_native_go_fuzzer github.com/the-sarge/cpace FuzzScalarMultVFY fuzz_scalar_mult_vfy
compile_native_go_fuzzer github.com/the-sarge/cpace FuzzMessageARoundTrip fuzz_message_a_round_trip
compile_native_go_fuzzer github.com/the-sarge/cpace FuzzMessageBRoundTrip fuzz_message_b_round_trip
compile_native_go_fuzzer github.com/the-sarge/cpace FuzzMessageCRoundTrip fuzz_message_c_round_trip
