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

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Try to parse various datetime-containing TOML structures
        let datetime_toml = format!("datetime = {}", s);
        let _ = toml::from_str::<toml::Value>(&datetime_toml);

        // Also test in table format
        let table_toml = format!("[table]\nfield = {}", s);
        let _ = toml::from_str::<toml::Value>(&table_toml);

        // Test in array format
        let array_toml = format!("array = [{}]", s);
        let _ = toml::from_str::<toml::Value>(&array_toml);
    }
});
