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
use netlink_packet_core::buffer::NetlinkBuffer;
use netlink_packet_core::constants::*;
use netlink_packet_core::done::DoneBuffer;
use netlink_packet_core::error::ErrorBuffer;
use netlink_packet_core::header::NetlinkHeader;

// Derive random data from fuzz input
#[derive(Arbitrary, Debug)]
struct FuzzInput {
    message_type: u16,
    sequence_number: u32,
    port_number: u32,
    buffer_data: Vec<u8>,
    payload_data: Vec<u8>,
}

fuzz_target!(|data: &[u8]| {
    // Initialize Unstructured for parsing the data
    let mut unstructured = Unstructured::new(data);

    // Attempt to parse the fuzz input structure
    if let Ok(fuzz_input) = FuzzInput::arbitrary(&mut unstructured) {
        // Fuzz NetlinkBuffer
        if let Ok(netlink_buffer) = NetlinkBuffer::new_checked(&fuzz_input.buffer_data) {
            let _ = netlink_buffer.payload_length();
            let _ = netlink_buffer.payload();
        }

        // Fuzz DoneBuffer
        if let Ok(done_buffer) = DoneBuffer::new_checked(&fuzz_input.buffer_data) {
            let _ = done_buffer.code();
            let _ = done_buffer.extended_ack();
        }

        // Fuzz ErrorBuffer
        if let Ok(error_buffer) = ErrorBuffer::new_checked(&fuzz_input.buffer_data) {
            let _code = error_buffer.code();
            let _payload = error_buffer.payload();
        }
    }
});
