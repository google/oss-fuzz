// Copyright 2021 Google LLC
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
//limitations under the License.
//
//################################################################################
#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate rustls;

use rustls::internal::msgs::persist;
use rustls::internal::msgs::codec::{Reader, Codec};

fn try_type<T>(data: &[u8]) where T: Codec {
    let mut rdr = Reader::init(data);
    T::read(&mut rdr);
}

fuzz_target!(|data: &[u8]| {
    try_type::<persist::ServerSessionValue>(data);
});
