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

use libfuzzer_sys::fuzz_target;
use utf8parse::{Parser, Receiver};

// Create dummy receiver for fuzzing
struct FuzzReceiver;
impl Receiver for FuzzReceiver {
    fn codepoint(&mut self, _c: char) {
        // Do nothing
    }

    fn invalid_sequence(&mut self) {
        // Do nothing
    }
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        // Skip this iteration if there is no data
        return;
    }

    let mut parser = Parser::new();
    let mut receiver = FuzzReceiver;

    // Process parsing
    fn process_byte_sequence(parser: &mut Parser, receiver: &mut FuzzReceiver, bytes: &[u8]) {
        for &byte in bytes {
            parser.advance(receiver, byte);
        }
    }

    let mut remaining_data = data;

    // Randomly create fuzz data with different constraint for fuzzing
    match remaining_data.get(0) {
        Some(&choice) => match choice % 3 {
            0 => {
                // Half and half
                let half = remaining_data.len() / 2;
                let (first_half, second_half) = remaining_data.split_at(half);
                process_byte_sequence(&mut parser, &mut receiver, first_half);
                process_byte_sequence(&mut parser, &mut receiver, second_half);
            }
            1 => {
                // Split data into uneven portion
                let chunk_size = (remaining_data[0] % 8) as usize + 1;
                let (chunk, rest) = remaining_data.split_at(remaining_data.len().min(chunk_size));
                process_byte_sequence(&mut parser, &mut receiver, chunk);
                remaining_data = rest;

                while !remaining_data.is_empty() {
                    let chunk_size = (remaining_data[0] % 6) as usize + 1;
                    let (chunk, rest) = remaining_data.split_at(remaining_data.len().min(chunk_size));
                    process_byte_sequence(&mut parser, &mut receiver, chunk);
                    remaining_data = rest;
                }
            }
            2 => {
                // Malformed input
                let incomplete_seq = vec![0xF0];
                process_byte_sequence(&mut parser, &mut receiver, &incomplete_seq);

                let chunk_size = (remaining_data[0] % 5) as usize + 1;
                let (chunk, _) = remaining_data.split_at(remaining_data.len().min(chunk_size));
                process_byte_sequence(&mut parser, &mut receiver, chunk);
            }
            _ => {
                // Should not reach here, fail safe
            }
        },
        None => return,
    }
});
