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
//
////////////////////////////////////////////////////////////////////////////////

#![no_main]

use libfuzzer_sys::fuzz_target;
use toml_edit::DocumentMut;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Parse as DocumentMut
        if let Ok(doc) = s.parse::<DocumentMut>() {
            // Serialize back to string
            let serialized = doc.to_string();

            // Parse again - should be idempotent
            if let Ok(doc2) = serialized.parse::<DocumentMut>() {
                let serialized2 = doc2.to_string();

                // The second serialization should match the first
                assert_eq!(
                    serialized, serialized2,
                    "Serialization is not idempotent"
                );
            }
        }
    }
});
