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
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct TestData {
    #[serde(default)]
    string: String,
    #[serde(default)]
    integer: i64,
    #[serde(default)]
    float: f64,
    #[serde(default)]
    boolean: bool,
    #[serde(default)]
    array: Vec<String>,
}

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Try to deserialize
        if let Ok(value) = toml::from_str::<TestData>(s) {
            // Serialize it back
            if let Ok(serialized) = toml::to_string(&value) {
                // Try to deserialize again - should succeed
                let _ = toml::from_str::<TestData>(&serialized);
            }
        }
    }
});
