// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Fuzz target: the `flatbuffers` Rust verifier plus the safe reader.
//!
//! All of the logic lives in `flatbuffers_rust_verifier_fuzzer::fuzz_one_input`
//! so that it can also be driven by `cargo miri run`; this file only wires it
//! into libFuzzer.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    flatbuffers_rust_verifier_fuzzer::fuzz_one_input(data);
});
