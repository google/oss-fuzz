// Copyright 2022 Google LLC
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
//###############################################################################

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::str;
use yaml_rust::*;

fuzz_target!(|data: &[u8]| {
    if let Ok(utf8) = str::from_utf8(data) {
        let _ = YamlLoader::load_from_str(utf8);
    }
});
