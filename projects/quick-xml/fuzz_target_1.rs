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
//###################
#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate quick_xml;

use quick_xml::Reader;
use quick_xml::events::Event;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    // fuzzed code goes here
    let cursor = Cursor::new(data);
    let mut reader = Reader::from_reader(cursor);
    let mut buf = vec![];
    loop {
        match reader.read_event(&mut buf) {
            Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e))=> {
                if e.unescaped().is_err() {
                    break;
                }
                for a in e.attributes() {
                    if a.ok().map_or(false, |a| a.unescaped_value().is_err()) {
                        break;
                    }
                }
            }
            Ok(Event::Text(ref e)) | Ok(Event::Comment(ref e))
            | Ok(Event::CData(ref e)) | Ok(Event::PI(ref e))
            | Ok(Event::DocType(ref e)) => {
                if e.unescaped().is_err() {
                    break;
                }
            }
            Ok(Event::Decl(ref e)) => {
                let _ = e.version();
                let _ = e.encoding();
                let _ = e.standalone();
            }
            Ok(Event::End(_)) => (),
            Ok(Event::Eof) | Err(..) => break,
        }
        buf.clear();
    }
});
