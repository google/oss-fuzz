// Copyright 2024 Google LLC
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

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use derive_arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use netlink_packet_utils::nla::{DefaultNla, NlaBuffer};
use netlink_packet_utils::parsers::*;
use netlink_packet_utils::traits::{Emitable, Parseable};

// Derive random data from fuzz input
#[derive(Arbitrary, Debug)]
struct FuzzInput {
    mac_data: [u8; 6],
    ip_data: Vec<u8>,
    utf8_data: Vec<u8>,
    nla_kind: u16,
    nla_value: Vec<u8>,
}

fuzz_target!(|data: &[u8]| {
    // Attempt to create a FuzzInput struct from the fuzzed data
    let mut unstructured = Unstructured::new(data);
    let fuzz_input = match FuzzInput::arbitrary(&mut unstructured) {
        Ok(input) => input,
        Err(_) => return,
    };

    // Fuzz parse_mac
    let _ = parse_mac(&fuzz_input.mac_data);

    // Fuzz parse_ip
    let _ = parse_ip(&fuzz_input.ip_data);

    // Fuzz parse_string
    let _ = parse_string(&fuzz_input.utf8_data);

    // Fuzz NlaBuffer
    if let Ok(nla_buf) = NlaBuffer::new_checked(&fuzz_input.nla_value) {
        let _ = nla_buf.kind();
        let _ = nla_buf.length();
        let _ = nla_buf.value_length();
    }

    // Fuzz DefaultNla
    let nla = DefaultNla::new(fuzz_input.nla_kind, fuzz_input.nla_value.clone());
    let mut emit_buffer = vec![0; nla.buffer_len()];
    nla.emit(&mut emit_buffer);

    // Fuzz DefaultNla parsing
    if let Ok(nla_buf) = NlaBuffer::new_checked(&fuzz_input.nla_value) {
        let _ = DefaultNla::parse(&nla_buf);
    }
});
